use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{info, warn};

use super::discovery::DiscoveredPeer;
use super::transport::Transport;

/// Bridges mDNS discovery to transport connections.
/// When a peer is discovered on the LAN, attempts to connect to it.
pub struct PeerManager {
    transport: Arc<Transport>,
}

impl PeerManager {
    pub fn new(transport: Arc<Transport>) -> Self {
        Self { transport }
    }

    /// Run the discovery handler loop: for each discovered peer,
    /// try to connect via QUIC if not already connected.
    pub async fn handle_discoveries(
        &self,
        mut discovered_rx: mpsc::Receiver<DiscoveredPeer>,
    ) {
        while let Some(peer) = discovered_rx.recv().await {
            // Skip if already connected
            if self.transport.is_connected(&peer.node_id).await {
                continue;
            }

            info!(
                peer_id = %peer.node_id,
                peer_name = %peer.name,
                addr = %peer.addr,
                "Discovered peer, connecting..."
            );

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
        }
    }
}
