use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::config::AppConfig;
use crate::metadata::MetadataDb;
use crate::net::protocol::Message;
use crate::net::transport::Transport;
use crate::store::BlobStore;
use crate::BlobHash;

/// Manages automatic cache eviction with two-tier size limits and last-copy safety.
pub struct CacheManager {
    db: Arc<MetadataDb>,
    store: Arc<BlobStore>,
    transport: Arc<Transport>,
    soft_limit: u64,
    hard_limit: u64,
    max_age_secs: u64,
    interval_secs: u64,
}

impl CacheManager {
    pub fn new(
        db: Arc<MetadataDb>,
        store: Arc<BlobStore>,
        transport: Arc<Transport>,
        config: &AppConfig,
    ) -> Self {
        Self {
            db,
            store,
            transport,
            soft_limit: config.cache_soft_limit,
            hard_limit: config.cache_hard_limit,
            max_age_secs: config.cache_max_age_secs,
            interval_secs: config.eviction_interval_secs,
        }
    }

    /// Run the periodic eviction loop. This never returns under normal operation.
    pub async fn run(self) {
        let mut tick = interval(Duration::from_secs(self.interval_secs));

        loop {
            tick.tick().await;

            let total = match self.db.total_blob_size() {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "Failed to query total blob size");
                    continue;
                }
            };

            if total <= self.soft_limit {
                debug!(total, soft_limit = self.soft_limit, "Cache below soft limit, no eviction needed");
                continue;
            }

            if total > self.hard_limit {
                info!(total, hard_limit = self.hard_limit, "Cache exceeds hard limit, running hard eviction");
                self.eviction_pass(total, self.hard_limit, None).await;
            } else {
                info!(total, soft_limit = self.soft_limit, "Cache exceeds soft limit, running soft eviction");
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                let cutoff = now - self.max_age_secs as i64;
                self.eviction_pass(total, self.soft_limit, Some(cutoff)).await;
            }
        }
    }

    /// Run one eviction pass, evicting blobs until total_size <= target_limit.
    /// If `older_than` is Some, only consider blobs with last_accessed < cutoff.
    async fn eviction_pass(&self, mut total: u64, target: u64, older_than: Option<i64>) {
        let candidates = match self.db.eviction_candidates(older_than) {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "Failed to query eviction candidates");
                return;
            }
        };

        let mut evicted_count = 0u64;
        let mut evicted_bytes = 0u64;

        for candidate in &candidates {
            if total <= target {
                break;
            }

            let hash = candidate.hash;
            let hex_hash = hex::encode(hash);

            if !self.check_peer_has_blob(&hash).await {
                debug!(%hex_hash, "Skipping eviction: no peer confirmed having blob");
                continue;
            }

            // Safe to evict: at least one peer has it
            if let Err(e) = self.store.remove(&hash) {
                warn!(%hex_hash, error = %e, "Failed to remove blob from store");
                continue;
            }
            if let Err(e) = self.db.remove_blob_record(&hash) {
                warn!(%hex_hash, error = %e, "Failed to remove blob record from DB");
                continue;
            }

            total = total.saturating_sub(candidate.size);
            evicted_count += 1;
            evicted_bytes += candidate.size;
            debug!(%hex_hash, size = candidate.size, "Evicted blob");
        }

        if evicted_count > 0 {
            info!(
                evicted_count,
                evicted_bytes,
                remaining = total,
                "Eviction pass complete"
            );
        }
    }

    /// Check if at least one connected peer has the given blob.
    /// Returns false if no peers are connected or none confirm.
    async fn check_peer_has_blob(&self, hash: &BlobHash) -> bool {
        let peers = self.transport.connected_peers().await;
        if peers.is_empty() {
            return false;
        }

        let query = Message::BlobHaveQuery { hash: *hash };

        // Query all peers in parallel with a 5-second timeout each
        let mut handles = Vec::with_capacity(peers.len());
        for (peer_id, _) in &peers {
            let transport = self.transport.clone();
            let msg = query.clone();
            let pid = *peer_id;
            handles.push(tokio::spawn(async move {
                match tokio::time::timeout(Duration::from_secs(5), transport.request(pid, &msg))
                    .await
                {
                    Ok(Ok(Message::BlobHaveResponse { have: true, .. })) => true,
                    _ => false,
                }
            }));
        }

        for handle in handles {
            if let Ok(true) = handle.await {
                return true;
            }
        }

        false
    }
}
