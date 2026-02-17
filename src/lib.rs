pub mod cache;
pub mod config;
pub mod fuse_fs;
pub mod metadata;
pub mod net;
pub mod store;
pub mod sync;

use sha2::{Digest, Sha256};

/// A SHA-256 hash used to identify blobs.
pub type BlobHash = [u8; 32];

/// Compute the SHA-256 fingerprint of a DER-encoded certificate, returned as hex.
pub fn cert_fingerprint(der: &[u8]) -> String {
    hex::encode(sha256(der))
}

/// Compute the SHA-256 hash of a byte slice.
pub fn sha256(data: &[u8]) -> BlobHash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[derive(Debug, thiserror::Error)]
pub enum NetFuseError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("Blob not found: {0}")]
    BlobNotFound(String),

    #[error("Entry not found: {0}")]
    EntryNotFound(String),

    #[error("Invalid path: {0}")]
    InvalidPath(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, NetFuseError>;
