use sha2::{Digest, Sha256};
use std::io::{self, Write};

use crate::BlobHash;

/// Wraps a writer and computes SHA-256 of all bytes written through it.
pub struct StreamingHasher<W: Write> {
    inner: W,
    hasher: Sha256,
    bytes_written: u64,
}

impl<W: Write> StreamingHasher<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes_written: 0,
        }
    }

    /// Finish hashing and return (hash, total bytes, inner writer).
    pub fn finish(self) -> (BlobHash, u64, W) {
        let hash: BlobHash = self.hasher.finalize().into();
        (hash, self.bytes_written, self.inner)
    }
}

impl<W: Write> Write for StreamingHasher<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes_written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
