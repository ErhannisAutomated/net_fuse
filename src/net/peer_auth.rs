use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Persistent record for a whitelisted/blacklisted peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub name: String,
    pub first_seen: String,
}

/// A peer awaiting user authorization decision.
#[derive(Debug, Clone)]
pub struct PendingPeer {
    pub fingerprint: String,
    pub name: String,
}

/// User's authorization decision for a peer.
#[derive(Debug, Clone, Copy)]
pub enum AuthDecision {
    Whitelist,
    SessionAllow,
    SessionIgnore,
    Blacklist,
}

/// Result of checking a peer's authorization status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResult {
    Allowed,
    Denied,
    Pending,
}

/// Persisted authorization data (whitelist + blacklist).
#[derive(Debug, Serialize, Deserialize, Default)]
struct PeerAuthData {
    whitelist: HashMap<String, PeerRecord>,
    blacklist: HashMap<String, PeerRecord>,
}

/// Manages peer authorization: persistent whitelist/blacklist + session-only decisions.
pub struct PeerAuth {
    data_path: PathBuf,
    our_fingerprint: String,
    whitelist: Mutex<HashMap<String, PeerRecord>>,
    blacklist: Mutex<HashMap<String, PeerRecord>>,
    session_allowed: Mutex<HashSet<String>>,
    session_ignored: Mutex<HashSet<String>>,
    pending_tx: mpsc::UnboundedSender<PendingPeer>,
}

impl PeerAuth {
    /// Create a new PeerAuth, loading persistent data from disk.
    pub fn new(
        data_path: PathBuf,
        our_fingerprint: String,
        pending_tx: mpsc::UnboundedSender<PendingPeer>,
    ) -> Self {
        let data = Self::load_from_file(&data_path);
        Self {
            data_path,
            our_fingerprint,
            whitelist: Mutex::new(data.whitelist),
            blacklist: Mutex::new(data.blacklist),
            session_allowed: Mutex::new(HashSet::new()),
            session_ignored: Mutex::new(HashSet::new()),
            pending_tx,
        }
    }

    /// Our own certificate fingerprint.
    pub fn our_fingerprint(&self) -> &str {
        &self.our_fingerprint
    }

    /// Check authorization status for a peer fingerprint.
    pub fn check(&self, fingerprint: &str) -> AuthResult {
        if self.whitelist.lock().contains_key(fingerprint) {
            return AuthResult::Allowed;
        }
        if self.session_allowed.lock().contains(fingerprint) {
            return AuthResult::Allowed;
        }
        if self.blacklist.lock().contains_key(fingerprint) {
            return AuthResult::Denied;
        }
        if self.session_ignored.lock().contains(fingerprint) {
            return AuthResult::Denied;
        }
        AuthResult::Pending
    }

    /// Submit a pending peer for user review.
    pub fn submit_pending(&self, fingerprint: String, name: String) {
        let _ = self.pending_tx.send(PendingPeer { fingerprint, name });
    }

    /// Apply a user's authorization decision for a peer.
    pub fn apply_decision(&self, fingerprint: &str, name: &str, decision: AuthDecision) {
        // Remove from all lists first
        self.whitelist.lock().remove(fingerprint);
        self.blacklist.lock().remove(fingerprint);
        self.session_allowed.lock().remove(fingerprint);
        self.session_ignored.lock().remove(fingerprint);

        let now = chrono_now();
        match decision {
            AuthDecision::Whitelist => {
                self.whitelist.lock().insert(
                    fingerprint.to_string(),
                    PeerRecord {
                        name: name.to_string(),
                        first_seen: now,
                    },
                );
                info!(fingerprint = &fingerprint[..16], name, "Peer whitelisted (persistent)");
            }
            AuthDecision::SessionAllow => {
                self.session_allowed.lock().insert(fingerprint.to_string());
                info!(fingerprint = &fingerprint[..16], name, "Peer session-allowed");
            }
            AuthDecision::SessionIgnore => {
                self.session_ignored.lock().insert(fingerprint.to_string());
                info!(fingerprint = &fingerprint[..16], name, "Peer session-ignored");
            }
            AuthDecision::Blacklist => {
                self.blacklist.lock().insert(
                    fingerprint.to_string(),
                    PeerRecord {
                        name: name.to_string(),
                        first_seen: now,
                    },
                );
                info!(fingerprint = &fingerprint[..16], name, "Peer blacklisted (persistent)");
            }
        }

        self.save();
    }

    fn load_from_file(path: &PathBuf) -> PeerAuthData {
        match std::fs::read_to_string(path) {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_else(|e| {
                warn!(?path, error = %e, "Failed to parse peer auth file, using defaults");
                PeerAuthData::default()
            }),
            Err(_) => PeerAuthData::default(),
        }
    }

    fn save(&self) {
        let data = PeerAuthData {
            whitelist: self.whitelist.lock().clone(),
            blacklist: self.blacklist.lock().clone(),
        };
        match serde_json::to_string_pretty(&data) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.data_path, json) {
                    warn!(error = %e, "Failed to save peer auth file");
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to serialize peer auth data");
            }
        }
    }
}

/// Simple ISO-8601 timestamp without pulling in chrono.
fn chrono_now() -> String {
    use std::time::SystemTime;
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    // Basic UTC timestamp: seconds since epoch formatted
    // For simplicity, store as unix timestamp string
    format!("{secs}")
}
