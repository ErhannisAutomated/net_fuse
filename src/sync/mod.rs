use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::metadata::types::{FileEntry, VectorClock};
use crate::metadata::{ApplyResult, MetadataDb};
use crate::net::protocol::Message;
use crate::net::transport::Transport;

/// Events emitted by FUSE callbacks to trigger sync broadcasts.
#[derive(Debug)]
pub enum SyncEvent {
    /// A file was created or updated (release, setattr).
    FileUpdated(FileEntry),
    /// A directory was created.
    DirCreated(FileEntry),
    /// A file was deleted (unlink).
    FileDeleted {
        path: String,
        vclock: VectorClock,
        origin_node: Uuid,
    },
    /// A directory was deleted (rmdir).
    DirDeleted {
        path: String,
        vclock: VectorClock,
        origin_node: Uuid,
    },
    /// An entry was renamed.
    Renamed {
        old_path: String,
        new_entry: FileEntry,
    },
}

/// The sync engine bridges local FUSE events to network broadcasts
/// and applies incoming remote messages to the local database.
pub struct SyncEngine {
    db: Arc<MetadataDb>,
    transport: Arc<Transport>,
    /// Receives local FUSE events to broadcast.
    local_rx: mpsc::UnboundedReceiver<SyncEvent>,
    /// Receives incoming messages from remote peers (via Transport).
    remote_rx: mpsc::Receiver<(Uuid, Message)>,
    /// Receives notification when a new peer connects (for initial sync).
    peer_connected_rx: mpsc::Receiver<Uuid>,
}

impl SyncEngine {
    pub fn new(
        db: Arc<MetadataDb>,
        transport: Arc<Transport>,
        local_rx: mpsc::UnboundedReceiver<SyncEvent>,
        remote_rx: mpsc::Receiver<(Uuid, Message)>,
        peer_connected_rx: mpsc::Receiver<Uuid>,
    ) -> Self {
        Self {
            db,
            transport,
            local_rx,
            remote_rx,
            peer_connected_rx,
        }
    }

    /// Run the sync engine loop. Processes local events, remote messages,
    /// and new peer connections concurrently.
    pub async fn run(mut self) {
        info!("SyncEngine started");

        loop {
            tokio::select! {
                // Handle local FUSE events -> broadcast to peers
                Some(event) = self.local_rx.recv() => {
                    self.handle_local_event(event).await;
                }

                // Handle incoming messages from peers
                Some((peer_id, msg)) = self.remote_rx.recv() => {
                    self.handle_remote_message(peer_id, msg).await;
                }

                // Handle new peer connections -> send full sync
                Some(peer_id) = self.peer_connected_rx.recv() => {
                    self.handle_peer_connected(peer_id).await;
                }

                else => {
                    info!("SyncEngine: all channels closed, shutting down");
                    break;
                }
            }
        }
    }

    /// Broadcast a local event to all peers.
    async fn handle_local_event(&self, event: SyncEvent) {
        let msg = match event {
            SyncEvent::FileUpdated(entry) | SyncEvent::DirCreated(entry) => {
                info!(
                    path = %entry.path,
                    hash = %entry.hash.map(|h| hex::encode(h)).unwrap_or_default(),
                    size = entry.size,
                    kind = ?entry.kind,
                    "Broadcasting PathUpdate"
                );
                Message::PathUpdate(entry)
            }
            SyncEvent::FileDeleted {
                path,
                vclock,
                origin_node,
            }
            | SyncEvent::DirDeleted {
                path,
                vclock,
                origin_node,
            } => {
                info!(%path, "Broadcasting PathDelete");
                Message::PathDelete {
                    path,
                    vclock,
                    origin_node,
                }
            }
            SyncEvent::Renamed {
                old_path,
                new_entry,
            } => {
                // Rename is broadcast as delete old + update new
                let delete_msg = Message::PathDelete {
                    path: old_path.clone(),
                    vclock: new_entry.vclock.clone(),
                    origin_node: new_entry.origin_node,
                };
                info!(%old_path, "Broadcasting PathDelete (rename old)");
                self.transport.broadcast(&delete_msg).await;

                info!(
                    path = %new_entry.path,
                    hash = %new_entry.hash.map(|h| hex::encode(h)).unwrap_or_default(),
                    size = new_entry.size,
                    "Broadcasting PathUpdate (rename new)"
                );
                Message::PathUpdate(new_entry)
            }
        };

        self.transport.broadcast(&msg).await;
    }

    /// Handle an incoming message from a peer.
    async fn handle_remote_message(&self, peer_id: Uuid, msg: Message) {
        match msg {
            Message::PathUpdate(entry) => {
                self.handle_path_update(peer_id, entry).await;
            }
            Message::PathDelete {
                path,
                vclock,
                origin_node,
            } => {
                self.handle_path_delete(peer_id, path, vclock, origin_node)
                    .await;
            }
            Message::FullSyncRequest => {
                self.handle_full_sync_request(peer_id).await;
            }
            Message::FullSyncResponse { entries } => {
                self.handle_full_sync_response(peer_id, entries).await;
            }
            other => {
                debug!(%peer_id, ?other, "Ignoring unhandled message type in SyncEngine");
            }
        }
    }

    /// Apply a remote PathUpdate and re-broadcast if it was applied (flood-fill).
    async fn handle_path_update(&self, peer_id: Uuid, entry: FileEntry) {
        let path = entry.path.clone();
        let hash_str = entry.hash.map(|h| hex::encode(h)).unwrap_or_default();
        let size = entry.size;
        match self.db.apply_remote_update(&entry) {
            Ok(ApplyResult::Applied) => {
                info!(
                    %peer_id, %path,
                    hash = %hash_str,
                    size = size,
                    kind = ?entry.kind,
                    "Applied remote update"
                );
                // Flood-fill: re-broadcast to other peers
                self.broadcast_except(peer_id, &Message::PathUpdate(entry))
                    .await;
            }
            Ok(ApplyResult::Ignored) => {
                debug!(
                    %peer_id, %path,
                    hash = %hash_str,
                    size = size,
                    "Ignored remote update (local is newer)"
                );
            }
            Ok(ApplyResult::Conflict) => {
                warn!(%peer_id, %path, "Conflict detected, both versions preserved");
                // Don't re-broadcast conflicts — the peer will also detect it
            }
            Err(e) => {
                warn!(%peer_id, %path, error = %e, "Error applying remote update");
            }
        }
    }

    /// Apply a remote PathDelete and re-broadcast if applied (flood-fill).
    async fn handle_path_delete(
        &self,
        peer_id: Uuid,
        path: String,
        vclock: VectorClock,
        origin_node: Uuid,
    ) {
        match self.db.apply_remote_delete(&path, &vclock) {
            Ok(ApplyResult::Applied) => {
                info!(%peer_id, %path, "Applied remote delete (file removed)");
                // Flood-fill
                let msg = Message::PathDelete {
                    path,
                    vclock,
                    origin_node,
                };
                self.broadcast_except(peer_id, &msg).await;
            }
            Ok(ApplyResult::Ignored) => {
                debug!(%peer_id, %path, "Ignored remote delete");
            }
            Ok(ApplyResult::Conflict) => {
                // apply_remote_delete doesn't produce Conflict, but handle it gracefully
                debug!(%peer_id, %path, "Delete conflict (kept local)");
            }
            Err(e) => {
                warn!(%peer_id, %path, error = %e, "Error applying remote delete");
            }
        }
    }

    /// Handle a new peer connection: send our full metadata to them.
    async fn handle_peer_connected(&self, peer_id: Uuid) {
        info!(%peer_id, "New peer connected, sending full sync");

        // Send FullSyncRequest to the peer to get their entries
        if let Err(e) = self
            .transport
            .send(peer_id, &Message::FullSyncRequest)
            .await
        {
            warn!(%peer_id, error = %e, "Failed to send FullSyncRequest");
            return;
        }

        // Also send our entries to them
        match self.db.all_entries() {
            Ok(entries) => {
                let msg = Message::FullSyncResponse { entries };
                if let Err(e) = self.transport.send(peer_id, &msg).await {
                    warn!(%peer_id, error = %e, "Failed to send FullSyncResponse");
                }
            }
            Err(e) => {
                warn!(%peer_id, error = %e, "Failed to read entries for full sync");
            }
        }
    }

    /// Handle a FullSyncRequest: send all our entries back.
    async fn handle_full_sync_request(&self, peer_id: Uuid) {
        info!(%peer_id, "Received FullSyncRequest, sending entries");
        match self.db.all_entries() {
            Ok(entries) => {
                let msg = Message::FullSyncResponse { entries };
                if let Err(e) = self.transport.send(peer_id, &msg).await {
                    warn!(%peer_id, error = %e, "Failed to send FullSyncResponse");
                }
            }
            Err(e) => {
                warn!(%peer_id, error = %e, "Failed to read entries for sync response");
            }
        }
    }

    /// Handle a FullSyncResponse: apply all entries from the peer.
    async fn handle_full_sync_response(&self, peer_id: Uuid, entries: Vec<FileEntry>) {
        info!(%peer_id, count = entries.len(), "Received FullSyncResponse");
        let mut applied = 0;
        let mut conflicts = 0;

        for entry in entries {
            match self.db.apply_remote_update(&entry) {
                Ok(ApplyResult::Applied) => applied += 1,
                Ok(ApplyResult::Conflict) => conflicts += 1,
                Ok(ApplyResult::Ignored) => {}
                Err(e) => {
                    warn!(path = %entry.path, error = %e, "Error applying sync entry");
                }
            }
        }

        info!(%peer_id, applied, conflicts, "Full sync complete");
    }

    /// Broadcast a message to all peers except the specified one (for flood-fill).
    async fn broadcast_except(&self, exclude: Uuid, msg: &Message) {
        let peers = self.transport.connected_peers().await;
        for (peer_id, _) in peers {
            if peer_id != exclude {
                if let Err(e) = self.transport.send(peer_id, msg).await {
                    warn!(%peer_id, error = %e, "Failed to forward message");
                }
            }
        }
    }
}
