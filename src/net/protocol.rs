use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::metadata::types::{FileEntry, VectorClock};
use crate::BlobHash;

/// All messages exchanged between NetFuse peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// Initial handshake: exchange node identity.
    Hello {
        node_id: Uuid,
        node_name: String,
        protocol_version: u32,
    },

    /// A path entry was created or updated.
    PathUpdate(FileEntry),

    /// A path was deleted.
    PathDelete {
        path: String,
        vclock: VectorClock,
        origin_node: Uuid,
    },

    /// Request a blob by hash.
    BlobRequest { hash: BlobHash },

    /// Response header for blob data (raw bytes follow on stream).
    BlobResponse { hash: BlobHash, size: u64 },

    /// Blob not available on this node.
    BlobNotFound { hash: BlobHash },

    /// Announce which blobs this node has (for location tracking).
    BlobInventory { hashes: Vec<BlobHash> },

    /// Ask if a peer still has a specific blob (for eviction safety).
    BlobHaveQuery { hash: BlobHash },

    /// Response to BlobHaveQuery.
    BlobHaveResponse { hash: BlobHash, have: bool },

    /// Request full metadata dump (used on initial connection).
    FullSyncRequest,

    /// Full metadata dump in response.
    FullSyncResponse { entries: Vec<FileEntry> },
}

/// Protocol version constant.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum message size (16 MiB) to prevent unbounded allocations.
const MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024;

/// Write a length-prefixed, postcard-serialized message to a QUIC send stream.
pub async fn write_message(
    send: &mut quinn::SendStream,
    msg: &Message,
) -> anyhow::Result<()> {
    let bytes = postcard::to_allocvec(msg)?;
    let len = bytes.len() as u32;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

/// Read a length-prefixed, postcard-serialized message from a QUIC recv stream.
pub async fn read_message(
    recv: &mut quinn::RecvStream,
) -> anyhow::Result<Message> {
    let mut len_buf = [0u8; 4];
    read_exact(recv, &mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);

    anyhow::ensure!(
        len <= MAX_MESSAGE_SIZE,
        "message too large: {} bytes",
        len
    );

    let mut buf = vec![0u8; len as usize];
    read_exact(recv, &mut buf).await?;
    Ok(postcard::from_bytes(&buf)?)
}

/// Read exactly `buf.len()` bytes from a QUIC RecvStream.
async fn read_exact(recv: &mut quinn::RecvStream, buf: &mut [u8]) -> anyhow::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        match recv.read(&mut buf[offset..]).await? {
            Some(n) => offset += n,
            None => anyhow::bail!("stream closed before all bytes received"),
        }
    }
    Ok(())
}
