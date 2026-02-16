use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use quinn::{Connection, Endpoint};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};
use uuid::Uuid;

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
}

impl Transport {
    /// Create a new QUIC transport, binding to the given address.
    pub async fn new(
        bind_addr: SocketAddr,
        node_id: Uuid,
        node_name: String,
        server_config: quinn::ServerConfig,
        client_config: quinn::ClientConfig,
    ) -> anyhow::Result<Self> {
        let mut endpoint = Endpoint::server(server_config, bind_addr)?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            node_id,
            node_name,
            connections: Arc::new(RwLock::new(HashMap::new())),
        })
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

        self.connections.write().await.insert(
            peer_id,
            PeerConn {
                connection,
                addr,
                name: peer_name.clone(),
            },
        );

        Ok((peer_id, peer_name))
    }

    /// Incoming handshake: we read their Hello first, then send ours.
    async fn handshake_incoming(
        &self,
        connection: Connection,
        addr: SocketAddr,
    ) -> anyhow::Result<(Uuid, String)> {
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

        self.connections.write().await.insert(
            peer_id,
            PeerConn {
                connection,
                addr,
                name: peer_name.clone(),
            },
        );

        Ok((peer_id, peer_name))
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
        let connections = self.connections.read().await;
        let peer = connections
            .get(&peer_id)
            .ok_or_else(|| anyhow::anyhow!("not connected to peer {}", peer_id))?;

        let mut send = peer.connection.open_uni().await?;
        protocol::write_message(&mut send, msg).await?;
        send.finish()?;
        Ok(())
    }

    /// Send a message and wait for a response (via bidirectional stream).
    pub async fn request(&self, peer_id: Uuid, msg: &Message) -> anyhow::Result<Message> {
        let connections = self.connections.read().await;
        let peer = connections
            .get(&peer_id)
            .ok_or_else(|| anyhow::anyhow!("not connected to peer {}", peer_id))?;

        let (mut send, mut recv) = peer.connection.open_bi().await?;
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

    /// Disconnect from a specific peer.
    pub async fn disconnect(&self, peer_id: &Uuid) {
        if let Some(peer) = self.connections.write().await.remove(peer_id) {
            peer.connection.close(0u32.into(), b"disconnect");
        }
    }
}
