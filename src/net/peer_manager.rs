use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::discovery::DiscoveredPeer;
use super::transport::Transport;

const COOLDOWN: Duration = Duration::from_secs(30);
const CLEANUP_THRESHOLD: Duration = Duration::from_secs(60);

/// Bridges mDNS discovery to transport connections.
/// When a peer is discovered on the LAN, attempts to connect to it.
pub struct PeerManager {
    transport: Arc<Transport>,
    recently_attempted: HashMap<SocketAddr, Instant>,
}

impl PeerManager {
    pub fn new(transport: Arc<Transport>) -> Self {
        Self {
            transport,
            recently_attempted: HashMap::new(),
        }
    }

    /// Run the discovery handler loop: for each discovered peer,
    /// try to connect via QUIC if not already connected.
    pub async fn handle_discoveries(
        mut self,
        mut discovered_rx: mpsc::Receiver<DiscoveredPeer>,
    ) {
        let mut cleanup_counter = 0u32;

        while let Some(peer) = discovered_rx.recv().await {
            // Skip if already connected
            if self.transport.is_connected(&peer.node_id).await {
                continue;
            }

            // Check cooldown
            if let Some(last) = self.recently_attempted.get(&peer.addr) {
                if last.elapsed() < COOLDOWN {
                    debug!(addr = %peer.addr, "Skipping peer (cooldown)");
                    continue;
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
                }
                Err(e) => {
                    warn!(
                        peer_id = %peer.node_id,
                        addr = %peer.addr,
                        error = %e,
                        "Failed to connect to discovered peer"
                    );
                }
            }

            // Periodic cleanup of old entries
            cleanup_counter += 1;
            if cleanup_counter % 20 == 0 {
                self.recently_attempted
                    .retain(|_, t| t.elapsed() < CLEANUP_THRESHOLD);
            }
        }
    }
}
