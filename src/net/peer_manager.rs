use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::discovery::DiscoveredPeer;
use super::transport::Transport;

const COOLDOWN: Duration = Duration::from_secs(30);
const CLEANUP_THRESHOLD: Duration = Duration::from_secs(60);

/// Bridges mDNS discovery to transport connections.
/// When a peer is discovered on the LAN, attempts to connect to it.
pub struct PeerManager {
    transport: Arc<Transport>,
    our_node_id: Uuid,
    recently_attempted: HashMap<SocketAddr, Instant>,
    /// Peers whose last connect attempt was rejected due to pending auth.
    /// Keyed by SocketAddr so we can retry them immediately after approval.
    awaiting_approval: HashMap<SocketAddr, DiscoveredPeer>,
}

impl PeerManager {
    pub fn new(transport: Arc<Transport>) -> Self {
        let our_node_id = transport.node_id();
        Self {
            transport,
            our_node_id,
            recently_attempted: HashMap::new(),
            awaiting_approval: HashMap::new(),
        }
    }

    /// Run the discovery handler loop: for each discovered peer,
    /// try to connect via QUIC if not already connected.
    ///
    /// `approved_rx` fires whenever the user approves a peer (Whitelist or
    /// SessionAllow), so we can immediately retry peers that were previously
    /// rejected by pending-auth without waiting for the next mDNS announcement.
    pub async fn handle_discoveries(
        mut self,
        mut discovered_rx: mpsc::Receiver<DiscoveredPeer>,
        mut approved_rx: mpsc::UnboundedReceiver<()>,
    ) {
        let mut cleanup_counter = 0u32;

        loop {
            tokio::select! {
                // New peer discovered via mDNS
                peer = discovered_rx.recv() => {
                    let Some(peer) = peer else { break };
                    self.try_connect(peer).await;

                    // Periodic cleanup of old cooldown entries
                    cleanup_counter += 1;
                    if cleanup_counter % 20 == 0 {
                        self.recently_attempted
                            .retain(|_, t| t.elapsed() < CLEANUP_THRESHOLD);
                    }
                }

                // User approved a peer — retry all pending-auth peers immediately
                result = approved_rx.recv() => {
                    if result.is_none() { break }
                    info!("Peer approved — retrying {} pending connection(s)", self.awaiting_approval.len());
                    let pending: Vec<DiscoveredPeer> = self.awaiting_approval.drain().map(|(_, p)| p).collect();
                    for peer in pending {
                        // Bypass cooldown: remove the old attempt record so try_connect proceeds
                        self.recently_attempted.remove(&peer.addr);
                        self.try_connect(peer).await;
                    }
                }
            }
        }
    }

    /// Attempt to connect to a peer, respecting the cooldown.
    /// Records the peer in `awaiting_approval` if the connection fails
    /// (which may indicate the peer needs auth approval).
    async fn try_connect(&mut self, peer: DiscoveredPeer) {
        // Skip self
        if peer.node_id == self.our_node_id {
            debug!(peer_id = %peer.node_id, addr = %peer.addr, "Skipping self-connection");
            return;
        }

        // Skip if already connected
        if self.transport.is_connected(&peer.node_id).await {
            return;
        }

        // Check cooldown
        if let Some(last) = self.recently_attempted.get(&peer.addr) {
            if last.elapsed() < COOLDOWN {
                debug!(addr = %peer.addr, "Skipping peer (cooldown)");
                return;
            }
        }

        info!(
            peer_id = %peer.node_id,
            peer_name = %peer.name,
            addr = %peer.addr,
            "Discovered peer, connecting..."
        );

        // Record attempt time
        self.recently_attempted.insert(peer.addr, Instant::now());

        match self.transport.connect(peer.addr).await {
            Ok((peer_id, peer_name)) => {
                info!(
                    peer_id = %peer_id,
                    peer_name = %peer_name,
                    "Successfully connected to peer"
                );
                // Connection succeeded — remove from awaiting approval if it was there
                self.awaiting_approval.remove(&peer.addr);
            }
            Err(e) => {
                warn!(
                    peer_id = %peer.node_id,
                    addr = %peer.addr,
                    error = %e,
                    "Failed to connect to peer"
                );
                // Keep this peer in awaiting_approval so an approval event can retry it.
                // (Covers both auth-pending rejections and transient network failures.)
                self.awaiting_approval.insert(peer.addr, peer);
            }
        }
    }
}
