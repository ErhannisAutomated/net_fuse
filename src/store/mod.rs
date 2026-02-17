pub mod hasher;

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::{BlobHash, NetFuseError, Result};
use hasher::StreamingHasher;

/// Content-addressed blob store.
///
/// Blobs are stored as `{base_dir}/{2-char-prefix}/{full-hex-hash}`.
pub struct BlobStore {
    base_dir: PathBuf,
    temp_dir: PathBuf,
}

impl BlobStore {
    pub fn new(base_dir: PathBuf) -> Result<Self> {
        let temp_dir = base_dir.join("tmp");
        fs::create_dir_all(&temp_dir)?;
        Ok(Self { base_dir, temp_dir })
    }

    /// Returns the on-disk path for a given hash.
    fn blob_path(&self, hash: &BlobHash) -> PathBuf {
        let hex = hex::encode(hash);
        self.base_dir.join(&hex[..2]).join(&hex)
    }

    /// Store data from a reader, returning the hash and size.
    pub fn store(&self, mut reader: impl Read) -> Result<(BlobHash, u64)> {
        let temp_path = self.temp_dir.join(uuid::Uuid::new_v4().to_string());
        let temp_file = File::create(&temp_path)?;
        let mut hasher = StreamingHasher::new(io::BufWriter::new(temp_file));

        io::copy(&mut reader, &mut hasher)?;
        hasher.flush()?;

        let (hash, size, _writer) = hasher.finish();
        let dest = self.blob_path(&hash);

        if dest.exists() {
            // Already stored — remove temp.
            let _ = fs::remove_file(&temp_path);
        } else {
            fs::create_dir_all(dest.parent().unwrap())?;
            fs::rename(&temp_path, &dest)?;
        }

        Ok((hash, size))
    }

    /// Store raw bytes, returning the hash and size.
    pub fn store_bytes(&self, data: &[u8]) -> Result<(BlobHash, u64)> {
        self.store(io::Cursor::new(data))
    }

    /// Read the full contents of a blob into memory.
    pub fn get(&self, hash: &BlobHash) -> Result<Vec<u8>> {
        let path = self.blob_path(hash);
        fs::read(&path).map_err(|_| NetFuseError::BlobNotFound(hex::encode(hash)))
    }

    /// Check if a blob exists locally.
    pub fn has(&self, hash: &BlobHash) -> bool {
        self.blob_path(hash).exists()
    }

    /// Open a blob for reading.
    pub fn open(&self, hash: &BlobHash) -> Result<File> {
        let path = self.blob_path(hash);
        File::open(&path).map_err(|_| NetFuseError::BlobNotFound(hex::encode(hash)))
    }

    /// Remove a blob from local storage.
    pub fn remove(&self, hash: &BlobHash) -> Result<()> {
        let path = self.blob_path(hash);
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    /// Create a new temp file for writing, returning (path, file).
    pub fn create_temp(&self) -> Result<(PathBuf, File)> {
        let path = self.temp_dir.join(uuid::Uuid::new_v4().to_string());
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        Ok((path, file))
    }

    /// Finalize a temp file: hash it, move to content-addressed location.
    /// Returns (hash, size).
    pub fn finalize_temp(&self, temp_path: &Path) -> Result<(BlobHash, u64)> {
        let file = File::open(temp_path)?;
        let mut reader = io::BufReader::new(file);

        // Hash the file
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        let mut size = 0u64;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            size += n as u64;
        }
        let hash: BlobHash = hasher.finalize().into();
        drop(reader);

        let dest = self.blob_path(&hash);
        if dest.exists() {
            let _ = fs::remove_file(temp_path);
        } else {
            fs::create_dir_all(dest.parent().unwrap())?;
            fs::rename(temp_path, &dest)?;
        }

        Ok((hash, size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn setup() -> (BlobStore, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let store = BlobStore::new(dir.path().join("blobs")).unwrap();
        (store, dir)
    }

    #[test]
    fn test_store_and_get() {
        let (store, _dir) = setup();
        let data = b"hello world";
        let (hash, size) = store.store_bytes(data).unwrap();

        assert_eq!(size, data.len() as u64);
        assert!(store.has(&hash));
        assert_eq!(store.get(&hash).unwrap(), data);
    }

    #[test]
    fn test_store_dedup() {
        let (store, _dir) = setup();
        let data = b"duplicate";
        let (h1, _) = store.store_bytes(data).unwrap();
        let (h2, _) = store.store_bytes(data).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_remove() {
        let (store, _dir) = setup();
        let (hash, _) = store.store_bytes(b"removeme").unwrap();
        assert!(store.has(&hash));
        store.remove(&hash).unwrap();
        assert!(!store.has(&hash));
    }

    #[test]
    fn test_open() {
        let (store, _dir) = setup();
        let data = b"openme";
        let (hash, _) = store.store_bytes(data).unwrap();
        let mut file = store.open(&hash).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, data);
    }

    #[test]
    fn test_finalize_temp() {
        let (store, _dir) = setup();
        let (temp_path, mut temp_file) = store.create_temp().unwrap();
        temp_file.write_all(b"temp data").unwrap();
        drop(temp_file);

        let (hash, size) = store.finalize_temp(&temp_path).unwrap();
        assert_eq!(size, 9);
        assert!(store.has(&hash));
        assert_eq!(store.get(&hash).unwrap(), b"temp data");
    }

    #[test]
    fn test_blob_not_found() {
        let (store, _dir) = setup();
        let fake_hash = [0u8; 32];
        assert!(!store.has(&fake_hash));
        assert!(store.get(&fake_hash).is_err());
    }
}
