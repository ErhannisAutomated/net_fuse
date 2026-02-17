use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::{Connection, Endpoint};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::store::BlobStore;
use crate::BlobHash;

use super::peer_auth::{AuthResult, PeerAuth};
use super::protocol::{self, Message, PROTOCOL_VERSION};

/// A connected peer.
struct PeerConn {
    connection: Connection,
    addr: SocketAddr,
    name: String,
}

/// QUIC transport layer: manages an endpoint and peer connections.
pub struct Transport {
    endpoint: Endpoint,
    node_id: Uuid,
    node_name: String,
    connections: Arc<RwLock<HashMap<Uuid, PeerConn>>>,
    /// Channel for forwarding incoming messages from peers to the SyncEngine.
    incoming_tx: mpsc::Sender<(Uuid, Message)>,
    /// Channel to notify when a new peer is connected (for initial sync).
    peer_connected_tx: mpsc::Sender<Uuid>,
    /// Blob store for serving blob requests from peers.
    blob_store: Arc<BlobStore>,
    /// Peer authorization manager.
    peer_auth: Arc<PeerAuth>,
}

impl Transport {
    /// Create a new QUIC transport, binding to the given address.
    pub async fn new(
        bind_addr: SocketAddr,
        node_id: Uuid,
        node_name: String,
        server_config: quinn::ServerConfig,
        client_config: quinn::ClientConfig,
        incoming_tx: mpsc::Sender<(Uuid, Message)>,
        peer_connected_tx: mpsc::Sender<Uuid>,
        blob_store: Arc<BlobStore>,
        peer_auth: Arc<PeerAuth>,
    ) -> anyhow::Result<Self> {
        // Configure keepalive to prevent idle timeout
        let mut server_transport = quinn::TransportConfig::default();
        server_transport.keep_alive_interval(Some(Duration::from_secs(10)));
        let mut client_transport = quinn::TransportConfig::default();
        client_transport.keep_alive_interval(Some(Duration::from_secs(10)));

        let mut server_config = server_config;
        server_config.transport_config(Arc::new(server_transport));

        let mut client_config = client_config;
        client_config.transport_config(Arc::new(client_transport));

        let mut endpoint = Endpoint::server(server_config, bind_addr)?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            node_id,
            node_name,
            connections: Arc::new(RwLock::new(HashMap::new())),
            incoming_tx,
            peer_connected_tx,
            blob_store,
            peer_auth,
        })
    }

    /// Extract the peer's certificate fingerprint from a QUIC connection.
    fn peer_fingerprint(connection: &Connection) -> anyhow::Result<String> {
        let identity = connection
            .peer_identity()
            .ok_or_else(|| anyhow::anyhow!("no peer identity available"))?;
        let certs: &Vec<rustls::pki_types::CertificateDer<'_>> = identity
            .downcast_ref()
            .ok_or_else(|| anyhow::anyhow!("unexpected peer identity type"))?;
        let cert = certs
            .first()
            .ok_or_else(|| anyhow::anyhow!("peer presented no certificates"))?;
        Ok(crate::cert_fingerprint(cert.as_ref()))
    }

    /// Check peer authorization by fingerprint. Returns Ok(()) if allowed, Err if denied/pending.
    /// The peer cert is available immediately after QUIC/TLS handshake, before Hello.
    fn check_peer_auth(
        &self,
        connection: &Connection,
    ) -> anyhow::Result<()> {
        let fingerprint = Self::peer_fingerprint(connection)?;

        // Self-connections are allowed through auth (caught later by Hello node_id check)
        if fingerprint == self.peer_auth.our_fingerprint() {
            return Ok(());
        }

        match self.peer_auth.check(&fingerprint) {
            AuthResult::Allowed => {
                info!(
                    fingerprint = &fingerprint[..16],
                    "Peer authorized"
                );
                Ok(())
            }
            AuthResult::Denied => {
                info!(
                    fingerprint = &fingerprint[..16],
                    "Peer denied by auth policy"
                );
                connection.close(0u32.into(), b"denied");
                anyhow::bail!("peer denied: {}", &fingerprint[..16])
            }
            AuthResult::Pending => {
                info!(
                    fingerprint = &fingerprint[..16],
                    "Peer pending authorization"
                );
                self.peer_auth
                    .submit_pending(fingerprint.clone(), "unknown".to_string());
                connection.close(0u32.into(), b"pending-auth");
                anyhow::bail!("peer pending auth: {}", &fingerprint[..16])
            }
        }
    }

    /// Connect to a peer by address. Performs QUIC handshake, then exchanges
    /// Hello messages. Returns (peer_node_id, peer_name) on success.
    pub async fn connect(&self, addr: SocketAddr) -> anyhow::Result<(Uuid, String)> {
        debug!(%addr, "Connecting to peer");
        let connection = self.endpoint.connect(addr, "netfuse")?.await?;
        self.handshake_outgoing(connection, addr).await
    }

    /// Outgoing handshake: we send Hello first, then read their Hello.
    async fn handshake_outgoing(
        &self,
        connection: Connection,
        addr: SocketAddr,
    ) -> anyhow::Result<(Uuid, String)> {
        // Check peer authorization BEFORE Hello exchange.
        // Cert is available immediately after QUIC/TLS handshake.
        // This ensures both sides prompt simultaneously for unknown peers.
        self.check_peer_auth(&connection)?;

        let (mut send, mut recv) = connection.open_bi().await?;

        // Send our Hello
        let hello = Message::Hello {
            node_id: self.node_id,
            node_name: self.node_name.clone(),
            protocol_version: PROTOCOL_VERSION,
        };
        protocol::write_message(&mut send, &hello).await?;
        send.finish()?;

        // Read their Hello
        let msg = protocol::read_message(&mut recv).await?;
        let (peer_id, peer_name) = match msg {
            Message::Hello {
                node_id,
                node_name,
                protocol_version,
            } => {
                info!(
                    peer_id = %node_id,
                    peer_name = %node_name,
                    protocol_version,
                    "Received Hello from peer"
                );
                (node_id, node_name)
            }
            other => anyhow::bail!("expected Hello, got {:?}", other),
        };

        // Don't connect to ourselves
        if peer_id == self.node_id {
            connection.close(0u32.into(), b"self-connection");
            anyhow::bail!("connected to self, closing");
        }

        // Start listening for incoming messages on this connection
        self.spawn_stream_listener(peer_id, connection.clone());

        self.connections.write().await.insert(
            peer_id,
            PeerConn {
                connection,
                addr,
                name: peer_name.clone(),
            },
        );

        // Notify SyncEngine of new peer
        let _ = self.peer_connected_tx.send(peer_id).await;

        Ok((peer_id, peer_name))
    }

    /// Incoming handshake: we read their Hello first, then send ours.
    async fn handshake_incoming(
        &self,
        connection: Connection,
        addr: SocketAddr,
    ) -> anyhow::Result<(Uuid, String)> {
        // Check peer authorization BEFORE Hello exchange.
        self.check_peer_auth(&connection)?;

        let (mut send, mut recv) = connection.accept_bi().await?;

        // Read their Hello
        let msg = protocol::read_message(&mut recv).await?;
        let (peer_id, peer_name) = match msg {
            Message::Hello {
                node_id,
                node_name,
                protocol_version,
            } => {
                info!(
                    peer_id = %node_id,
                    peer_name = %node_name,
                    protocol_version,
                    %addr,
                    "Incoming Hello from peer"
                );
                (node_id, node_name)
            }
            other => anyhow::bail!("expected Hello, got {:?}", other),
        };

        // Send our Hello
        let hello = Message::Hello {
            node_id: self.node_id,
            node_name: self.node_name.clone(),
            protocol_version: PROTOCOL_VERSION,
        };
        protocol::write_message(&mut send, &hello).await?;
        send.finish()?;

        // Don't connect to ourselves
        if peer_id == self.node_id {
            connection.close(0u32.into(), b"self-connection");
            anyhow::bail!("incoming connection from self, closing");
        }

        // Start listening for incoming messages on this connection
        self.spawn_stream_listener(peer_id, connection.clone());

        self.connections.write().await.insert(
            peer_id,
            PeerConn {
                connection,
                addr,
                name: peer_name.clone(),
            },
        );

        // Notify SyncEngine of new peer
        let _ = self.peer_connected_tx.send(peer_id).await;

        Ok((peer_id, peer_name))
    }

    /// Spawn background tasks that listen for incoming streams on a connection.
    /// - Unidirectional streams carry sync messages forwarded to SyncEngine.
    /// - Bidirectional streams carry blob requests served from the local BlobStore.
    /// When the connection closes, the peer is removed from the connections map.
    fn spawn_stream_listener(&self, peer_id: Uuid, connection: Connection) {
        let connections = self.connections.clone();

        // Uni-directional: sync messages
        let incoming_tx = self.incoming_tx.clone();
        let conn_uni = connection.clone();
        tokio::spawn(async move {
            loop {
                match conn_uni.accept_uni().await {
                    Ok(mut recv) => {
                        let tx = incoming_tx.clone();
                        tokio::spawn(async move {
                            match protocol::read_message(&mut recv).await {
                                Ok(msg) => {
                                    debug!(%peer_id, ?msg, "Received message from peer");
                                    if let Err(e) = tx.send((peer_id, msg)).await {
                                        debug!("Failed to forward message: {}", e);
                                    }
                                }
                                Err(e) => {
                                    warn!(%peer_id, error = %e, "Error reading from peer stream");
                                }
                            }
                        });
                    }
                    Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                        info!(%peer_id, "Peer connection closed (uni)");
                        break;
                    }
                    Err(e) => {
                        warn!(%peer_id, error = %e, "Uni stream accept error, peer disconnected");
                        break;
                    }
                }
            }
            // Clean up dead connection so PeerManager can reconnect
            connections.write().await.remove(&peer_id);
        });

        // Bi-directional: blob requests
        let blob_store = self.blob_store.clone();
        let connections = self.connections.clone();
        tokio::spawn(async move {
            loop {
                match connection.accept_bi().await {
                    Ok((mut send, mut recv)) => {
                        let store = blob_store.clone();
                        tokio::spawn(async move {
                            if let Err(e) =
                                Self::handle_bi_stream(peer_id, &mut send, &mut recv, &store).await
                            {
                                warn!(%peer_id, error = %e, "Error handling bi-stream");
                            }
                        });
                    }
                    Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                        info!(%peer_id, "Peer connection closed (bi)");
                        break;
                    }
                    Err(e) => {
                        warn!(%peer_id, error = %e, "Bi stream accept error, peer disconnected");
                        break;
                    }
                }
            }
            // Clean up dead connection so PeerManager can reconnect
            connections.write().await.remove(&peer_id);
        });
    }

    /// Handle a single incoming bi-directional stream (blob request/response).
    async fn handle_bi_stream(
        peer_id: Uuid,
        send: &mut quinn::SendStream,
        recv: &mut quinn::RecvStream,
        store: &BlobStore,
    ) -> anyhow::Result<()> {
        let msg = protocol::read_message(recv).await?;

        match msg {
            Message::BlobRequest { hash } => {
                let hex_hash = hex::encode(hash);
                if store.has(&hash) {
                    let data = store.get(&hash)?;
                    let size = data.len() as u64;
                    debug!(%peer_id, %hex_hash, size, "Serving blob to peer");

                    let resp = Message::BlobResponse { hash, size };
                    protocol::write_message(send, &resp).await?;
                    send.write_all(&data).await?;
                    send.finish()?;
                } else {
                    debug!(%peer_id, %hex_hash, "Blob not found, sending BlobNotFound");
                    let resp = Message::BlobNotFound { hash };
                    protocol::write_message(send, &resp).await?;
                    send.finish()?;
                }
            }
            Message::BlobHaveQuery { hash } => {
                let have = store.has(&hash);
                debug!(%peer_id, hash = %hex::encode(hash), have, "BlobHaveQuery");
                let resp = Message::BlobHaveResponse { hash, have };
                protocol::write_message(send, &resp).await?;
                send.finish()?;
            }
            other => {
                warn!(%peer_id, ?other, "Unexpected message on bi-stream");
            }
        }

        Ok(())
    }

    /// Accept incoming connections in a loop. Sends (peer_id, peer_name)
    /// on the channel for each successful connection.
    pub async fn accept_loop(
        self: Arc<Self>,
        on_peer_connected: mpsc::Sender<(Uuid, String)>,
    ) {
        loop {
            let Some(incoming) = self.endpoint.accept().await else {
                info!("QUIC endpoint closed, stopping accept loop");
                break;
            };

            let transport = self.clone();
            let tx = on_peer_connected.clone();

            tokio::spawn(async move {
                let addr = incoming.remote_address();
                match incoming.await {
                    Ok(connection) => {
                        match transport.handshake_incoming(connection, addr).await {
                            Ok((peer_id, peer_name)) => {
                                let _ = tx.send((peer_id, peer_name)).await;
                            }
                            Err(e) => {
                                warn!(%addr, error = %e, "Incoming handshake failed");
                            }
                        }
                    }
                    Err(e) => {
                        warn!(%addr, error = %e, "Failed to accept QUIC connection");
                    }
                }
            });
        }
    }

    /// Send a message to a specific peer (fire-and-forget via unidirectional stream).
    pub async fn send(&self, peer_id: Uuid, msg: &Message) -> anyhow::Result<()> {
        let conn = {
            let connections = self.connections.read().await;
            connections
                .get(&peer_id)
                .ok_or_else(|| anyhow::anyhow!("not connected to peer {}", peer_id))?
                .connection
                .clone()
        };

        let mut send = conn.open_uni().await?;
        protocol::write_message(&mut send, msg).await?;
        send.finish()?;
        Ok(())
    }

    /// Send a message and wait for a response (via bidirectional stream).
    pub async fn request(&self, peer_id: Uuid, msg: &Message) -> anyhow::Result<Message> {
        let conn = {
            let connections = self.connections.read().await;
            connections
                .get(&peer_id)
                .ok_or_else(|| anyhow::anyhow!("not connected to peer {}", peer_id))?
                .connection
                .clone()
        };

        let (mut send, mut recv) = conn.open_bi().await?;
        protocol::write_message(&mut send, msg).await?;
        send.finish()?;

        protocol::read_message(&mut recv).await
    }

    /// Broadcast a message to all connected peers.
    pub async fn broadcast(&self, msg: &Message) {
        let peer_ids: Vec<Uuid> = {
            let connections = self.connections.read().await;
            connections.keys().copied().collect()
        };

        for peer_id in peer_ids {
            if let Err(e) = self.send(peer_id, msg).await {
                warn!(%peer_id, error = %e, "Failed to send to peer");
            }
        }
    }

    /// Check if we're connected to a given peer.
    pub async fn is_connected(&self, peer_id: &Uuid) -> bool {
        self.connections.read().await.contains_key(peer_id)
    }

    /// List connected peers as (id, name) pairs.
    pub async fn connected_peers(&self) -> Vec<(Uuid, String)> {
        self.connections
            .read()
            .await
            .iter()
            .map(|(&id, pc)| (id, pc.name.clone()))
            .collect()
    }

    /// Get our local listen address.
    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    /// Fetch a blob from a specific peer by opening a bi-directional stream.
    pub async fn fetch_blob(&self, peer_id: Uuid, hash: &BlobHash) -> anyhow::Result<Vec<u8>> {
        let conn = {
            let connections = self.connections.read().await;
            connections
                .get(&peer_id)
                .ok_or_else(|| anyhow::anyhow!("not connected to peer {}", peer_id))?
                .connection
                .clone()
        };

        let (mut send, mut recv) = conn.open_bi().await?;

        let req = Message::BlobRequest { hash: *hash };
        protocol::write_message(&mut send, &req).await?;
        send.finish()?;

        let resp = protocol::read_message(&mut recv).await?;
        match resp {
            Message::BlobResponse { hash: _, size } => {
                let mut data = vec![0u8; size as usize];
                protocol::read_exact(&mut recv, &mut data).await?;
                Ok(data)
            }
            Message::BlobNotFound { .. } => {
                anyhow::bail!("peer {} does not have blob {}", peer_id, hex::encode(hash))
            }
            other => anyhow::bail!("unexpected response to BlobRequest: {:?}", other),
        }
    }

    /// Disconnect from a specific peer.
    pub async fn disconnect(&self, peer_id: &Uuid) {
        if let Some(peer) = self.connections.write().await.remove(peer_id) {
            peer.connection.close(0u32.into(), b"disconnect");
        }
    }
}
