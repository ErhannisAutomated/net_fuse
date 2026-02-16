pub mod schema;
pub mod types;

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use rusqlite::{Connection, params};

use crate::{BlobHash, NetFuseError, Result};
use types::{BlobRecord, EntryKind, FileEntry, Timestamp, VectorClock};

/// Result of applying a remote update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyResult {
    /// The remote update was applied (inserted or replaced).
    Applied,
    /// The remote update was ignored (local is newer or equal).
    Ignored,
    /// The update caused a conflict (both versions preserved).
    Conflict,
}

/// Thread-safe SQLite-backed metadata database.
pub struct MetadataDb {
    conn: Mutex<Connection>,
    node_id: uuid::Uuid,
}

impl MetadataDb {
    /// Open (or create) the database at the given path.
    pub fn open(db_path: &Path, node_id: uuid::Uuid) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        schema::init_schema(&conn)?;
        schema::ensure_root(&conn, node_id)?;
        Ok(Self {
            conn: Mutex::new(conn),
            node_id,
        })
    }

    /// Open an in-memory database (for testing).
    pub fn open_memory(node_id: uuid::Uuid) -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        schema::init_schema(&conn)?;
        schema::ensure_root(&conn, node_id)?;
        Ok(Self {
            conn: Mutex::new(conn),
            node_id,
        })
    }

    pub fn node_id(&self) -> uuid::Uuid {
        self.node_id
    }

    /// Get a file entry by path.
    pub fn get_entry(&self, path: &str) -> Result<Option<FileEntry>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT path, parent_path, hash, size, mtime_secs, mtime_nanos,
                    ctime_secs, ctime_nanos, permissions, kind, vclock,
                    origin_node, conflict_id
             FROM files WHERE path = ?1",
        )?;

        let result = stmt.query_row(params![path], |row| {
            Ok(row_to_file_entry(row)?)
        });

        match result {
            Ok(entry) => Ok(Some(entry)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Insert or update a file entry.
    pub fn upsert_entry(&self, entry: &FileEntry) -> Result<()> {
        let conn = self.conn.lock();
        let vclock_bytes = entry.vclock.serialize();
        let hash_bytes = entry.hash.as_ref().map(|h| h.as_slice());
        let conflict_bytes = entry.conflict_id.map(|id| id.as_bytes().to_vec());

        conn.execute(
            "INSERT INTO files (path, parent_path, hash, size, mtime_secs, mtime_nanos,
             ctime_secs, ctime_nanos, permissions, kind, vclock, origin_node, conflict_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(path) DO UPDATE SET
                parent_path = excluded.parent_path,
                hash = excluded.hash,
                size = excluded.size,
                mtime_secs = excluded.mtime_secs,
                mtime_nanos = excluded.mtime_nanos,
                ctime_secs = excluded.ctime_secs,
                ctime_nanos = excluded.ctime_nanos,
                permissions = excluded.permissions,
                kind = excluded.kind,
                vclock = excluded.vclock,
                origin_node = excluded.origin_node,
                conflict_id = excluded.conflict_id",
            params![
                entry.path,
                entry.parent_path,
                hash_bytes,
                entry.size as i64,
                entry.mtime.secs,
                entry.mtime.nanos,
                entry.ctime.secs,
                entry.ctime.nanos,
                entry.permissions as i64,
                entry.kind as u8,
                vclock_bytes,
                entry.origin_node.as_bytes().as_slice(),
                conflict_bytes,
            ],
        )?;
        Ok(())
    }

    /// Delete an entry by path.
    pub fn delete_entry(&self, path: &str) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM files WHERE path = ?1", params![path])?;
        Ok(())
    }

    /// List direct children of a directory.
    pub fn list_children(&self, parent_path: &str) -> Result<Vec<FileEntry>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT path, parent_path, hash, size, mtime_secs, mtime_nanos,
                    ctime_secs, ctime_nanos, permissions, kind, vclock,
                    origin_node, conflict_id
             FROM files WHERE parent_path = ?1",
        )?;

        let entries = stmt
            .query_map(params![parent_path], |row| row_to_file_entry(row))?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(entries)
    }

    /// Register a blob in the blob tracking table.
    pub fn register_blob(&self, hash: &BlobHash, size: u64, local_path: &str) -> Result<()> {
        let conn = self.conn.lock();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        conn.execute(
            "INSERT INTO blobs (hash, size, local_path, last_accessed, ref_count)
             VALUES (?1, ?2, ?3, ?4, 1)
             ON CONFLICT(hash) DO UPDATE SET
                ref_count = blobs.ref_count + 1,
                last_accessed = excluded.last_accessed",
            params![hash.as_slice(), size as i64, local_path, now],
        )?;
        Ok(())
    }

    /// Update the last_accessed time for a blob.
    pub fn touch_blob(&self, hash: &BlobHash) -> Result<()> {
        let conn = self.conn.lock();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        conn.execute(
            "UPDATE blobs SET last_accessed = ?1 WHERE hash = ?2",
            params![now, hash.as_slice()],
        )?;
        Ok(())
    }

    /// Decrement the ref_count for a blob.
    pub fn deref_blob(&self, hash: &BlobHash) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE blobs SET ref_count = MAX(0, ref_count - 1) WHERE hash = ?1",
            params![hash.as_slice()],
        )?;
        Ok(())
    }

    /// Get a blob record.
    pub fn get_blob(&self, hash: &BlobHash) -> Result<Option<BlobRecord>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT hash, size, local_path, last_accessed, ref_count FROM blobs WHERE hash = ?1",
        )?;

        let result = stmt.query_row(params![hash.as_slice()], |row| {
            let hash_bytes: Vec<u8> = row.get(0)?;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hash_bytes);
            Ok(BlobRecord {
                hash,
                size: row.get::<_, i64>(1)? as u64,
                local_path: row.get(2)?,
                last_accessed: row.get(3)?,
                ref_count: row.get(4)?,
            })
        });

        match result {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get all file paths in the database.
    pub fn all_paths(&self) -> Result<Vec<String>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("SELECT path FROM files ORDER BY path")?;
        let paths = stmt
            .query_map([], |row| row.get(0))?
            .collect::<std::result::Result<Vec<String>, _>>()?;
        Ok(paths)
    }

    /// Get all file entries in the database (for full sync).
    pub fn all_entries(&self) -> Result<Vec<FileEntry>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT path, parent_path, hash, size, mtime_secs, mtime_nanos,
                    ctime_secs, ctime_nanos, permissions, kind, vclock,
                    origin_node, conflict_id
             FROM files ORDER BY path",
        )?;

        let entries = stmt
            .query_map([], |row| row_to_file_entry(row))?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(entries)
    }

    /// Apply a remote file entry update. Returns what happened.
    ///
    /// - If no local entry exists, insert the remote one.
    /// - If local vclock < remote vclock, replace with remote.
    /// - If local vclock > remote vclock, ignore (we're newer).
    /// - If concurrent (neither dominates), create a conflict entry.
    pub fn apply_remote_update(&self, remote: &FileEntry) -> Result<ApplyResult> {
        let local = self.get_entry(&remote.path)?;

        match local {
            None => {
                // No local entry — just insert
                self.upsert_entry(remote)?;
                Ok(ApplyResult::Applied)
            }
            Some(local_entry) => {
                match local_entry.vclock.partial_cmp(&remote.vclock) {
                    Some(std::cmp::Ordering::Less) => {
                        // Remote dominates — replace
                        self.upsert_entry(remote)?;
                        Ok(ApplyResult::Applied)
                    }
                    Some(std::cmp::Ordering::Equal) | Some(std::cmp::Ordering::Greater) => {
                        // Local is equal or newer — ignore
                        Ok(ApplyResult::Ignored)
                    }
                    None => {
                        // Concurrent — conflict!
                        self.create_conflict(&local_entry, remote)?;
                        Ok(ApplyResult::Conflict)
                    }
                }
            }
        }
    }

    /// Apply a remote delete. Returns what happened.
    pub fn apply_remote_delete(
        &self,
        path: &str,
        remote_vclock: &types::VectorClock,
    ) -> Result<ApplyResult> {
        let local = self.get_entry(path)?;

        match local {
            None => {
                // Already gone
                Ok(ApplyResult::Ignored)
            }
            Some(local_entry) => {
                match local_entry.vclock.partial_cmp(remote_vclock) {
                    Some(std::cmp::Ordering::Less) | Some(std::cmp::Ordering::Equal) => {
                        // Remote dominates or equal — delete
                        self.delete_entry(path)?;
                        Ok(ApplyResult::Applied)
                    }
                    Some(std::cmp::Ordering::Greater) => {
                        // Local is newer — ignore
                        Ok(ApplyResult::Ignored)
                    }
                    None => {
                        // Concurrent — keep local, ignore delete
                        // (local was modified concurrently, preserve it)
                        Ok(ApplyResult::Ignored)
                    }
                }
            }
        }
    }

    /// Create conflict entries for two concurrent versions.
    /// Keeps the local entry at the original path (with merged vclock),
    /// and adds a `.conflict.<origin-node-short>` entry for the remote version.
    fn create_conflict(&self, local: &FileEntry, remote: &FileEntry) -> Result<()> {
        // Merge vclocks for the local entry
        let mut merged_vclock = local.vclock.clone();
        merged_vclock.merge(&remote.vclock);

        let mut local_updated = local.clone();
        local_updated.vclock = merged_vclock.clone();
        local_updated.conflict_id = Some(uuid::Uuid::new_v4());
        self.upsert_entry(&local_updated)?;

        // Create conflict entry for the remote version
        let origin_short = &remote.origin_node.to_string()[..8];
        let conflict_path = format!("{}.conflict.{}", remote.path, origin_short);
        let mut conflict_entry = remote.clone();
        conflict_entry.path = conflict_path;
        conflict_entry.vclock = merged_vclock;
        conflict_entry.conflict_id = Some(uuid::Uuid::new_v4());
        self.upsert_entry(&conflict_entry)?;

        Ok(())
    }

    /// Rename: update path and parent_path for an entry (and children if directory).
    pub fn rename_entry(&self, old_path: &str, new_path: &str, new_parent: &str) -> Result<()> {
        let conn = self.conn.lock();

        // Check if old entry exists
        let kind: Option<u8> = conn
            .query_row(
                "SELECT kind FROM files WHERE path = ?1",
                params![old_path],
                |row| row.get(0),
            )
            .ok();

        let Some(kind) = kind else {
            return Err(NetFuseError::EntryNotFound(old_path.to_string()));
        };

        // Update the entry itself
        let now = Timestamp::now();
        conn.execute(
            "UPDATE files SET path = ?1, parent_path = ?2, mtime_secs = ?3, mtime_nanos = ?4
             WHERE path = ?5",
            params![new_path, new_parent, now.secs, now.nanos, old_path],
        )?;

        // If directory, update all descendants
        if kind == EntryKind::Directory as u8 {
            let old_prefix = if old_path == "/" {
                "/".to_string()
            } else {
                format!("{}/", old_path)
            };
            let new_prefix = if new_path == "/" {
                "/".to_string()
            } else {
                format!("{}/", new_path)
            };

            // Get all descendants
            let mut stmt = conn.prepare(
                "SELECT path, parent_path FROM files WHERE path LIKE ?1 || '%'",
            )?;
            let children: Vec<(String, String)> = stmt
                .query_map(params![old_prefix], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;

            for (child_path, child_parent) in children {
                let new_child_path = format!("{}{}", new_prefix, &child_path[old_prefix.len()..]);
                let new_child_parent = if child_parent == old_path {
                    new_path.to_string()
                } else {
                    format!(
                        "{}{}",
                        new_prefix,
                        &child_parent[old_prefix.len()..]
                    )
                };
                conn.execute(
                    "UPDATE files SET path = ?1, parent_path = ?2 WHERE path = ?3",
                    params![new_child_path, new_child_parent, child_path],
                )?;
            }
        }

        Ok(())
    }
}

fn row_to_file_entry(row: &rusqlite::Row) -> rusqlite::Result<FileEntry> {
    let path: String = row.get(0)?;
    let parent_path: String = row.get(1)?;
    let hash_bytes: Option<Vec<u8>> = row.get(2)?;
    let size: i64 = row.get(3)?;
    let mtime_secs: i64 = row.get(4)?;
    let mtime_nanos: u32 = row.get(5)?;
    let ctime_secs: i64 = row.get(6)?;
    let ctime_nanos: u32 = row.get(7)?;
    let permissions: i64 = row.get(8)?;
    let kind_val: u8 = row.get(9)?;
    let vclock_bytes: Vec<u8> = row.get(10)?;
    let origin_bytes: Vec<u8> = row.get(11)?;
    let conflict_bytes: Option<Vec<u8>> = row.get(12)?;

    let hash = hash_bytes.map(|b| {
        let mut h = [0u8; 32];
        h.copy_from_slice(&b);
        h
    });

    let kind = EntryKind::from_u8(kind_val).unwrap_or(EntryKind::File);
    let vclock =
        VectorClock::deserialize(&vclock_bytes).unwrap_or_default();

    let mut origin = [0u8; 16];
    origin.copy_from_slice(&origin_bytes);
    let origin_node = uuid::Uuid::from_bytes(origin);

    let conflict_id = conflict_bytes.map(|b| {
        let mut id = [0u8; 16];
        id.copy_from_slice(&b);
        uuid::Uuid::from_bytes(id)
    });

    Ok(FileEntry {
        path,
        parent_path,
        hash,
        size: size as u64,
        mtime: Timestamp {
            secs: mtime_secs,
            nanos: mtime_nanos,
        },
        ctime: Timestamp {
            secs: ctime_secs,
            nanos: ctime_nanos,
        },
        permissions: permissions as u32,
        kind,
        vclock,
        origin_node,
        conflict_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> MetadataDb {
        let node_id = uuid::Uuid::new_v4();
        MetadataDb::open_memory(node_id).unwrap()
    }

    #[test]
    fn test_root_exists() {
        let db = setup();
        let root = db.get_entry("/").unwrap();
        assert!(root.is_some());
        let root = root.unwrap();
        assert_eq!(root.path, "/");
        assert_eq!(root.kind, EntryKind::Directory);
    }

    #[test]
    fn test_upsert_and_get() {
        let db = setup();
        let entry = FileEntry::new_dir("/test".to_string(), "/".to_string(), db.node_id());
        db.upsert_entry(&entry).unwrap();

        let got = db.get_entry("/test").unwrap().unwrap();
        assert_eq!(got.path, "/test");
        assert_eq!(got.kind, EntryKind::Directory);
        assert_eq!(got.parent_path, "/");
    }

    #[test]
    fn test_list_children() {
        let db = setup();
        let dir = FileEntry::new_dir("/sub".to_string(), "/".to_string(), db.node_id());
        db.upsert_entry(&dir).unwrap();

        let hash = [42u8; 32];
        let file = FileEntry::new_file("/sub/file.txt".to_string(), "/sub".to_string(), hash, 100, db.node_id());
        db.upsert_entry(&file).unwrap();

        let children = db.list_children("/sub").unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].path, "/sub/file.txt");

        let root_children = db.list_children("/").unwrap();
        assert_eq!(root_children.len(), 1);
        assert_eq!(root_children[0].path, "/sub");
    }

    #[test]
    fn test_delete_entry() {
        let db = setup();
        let entry = FileEntry::new_dir("/gone".to_string(), "/".to_string(), db.node_id());
        db.upsert_entry(&entry).unwrap();
        assert!(db.get_entry("/gone").unwrap().is_some());

        db.delete_entry("/gone").unwrap();
        assert!(db.get_entry("/gone").unwrap().is_none());
    }

    #[test]
    fn test_blob_tracking() {
        let db = setup();
        let hash = [1u8; 32];
        db.register_blob(&hash, 1024, "/blobs/01/0101..").unwrap();

        let record = db.get_blob(&hash).unwrap().unwrap();
        assert_eq!(record.size, 1024);
        assert_eq!(record.ref_count, 1);

        // Register again bumps ref count
        db.register_blob(&hash, 1024, "/blobs/01/0101..").unwrap();
        let record = db.get_blob(&hash).unwrap().unwrap();
        assert_eq!(record.ref_count, 2);

        db.deref_blob(&hash).unwrap();
        let record = db.get_blob(&hash).unwrap().unwrap();
        assert_eq!(record.ref_count, 1);
    }

    #[test]
    fn test_rename_entry() {
        let db = setup();
        let dir = FileEntry::new_dir("/a".to_string(), "/".to_string(), db.node_id());
        db.upsert_entry(&dir).unwrap();

        let hash = [10u8; 32];
        let file = FileEntry::new_file("/a/f.txt".to_string(), "/a".to_string(), hash, 50, db.node_id());
        db.upsert_entry(&file).unwrap();

        db.rename_entry("/a", "/b", "/").unwrap();

        assert!(db.get_entry("/a").unwrap().is_none());
        assert!(db.get_entry("/b").unwrap().is_some());
        // Child should also be renamed
        assert!(db.get_entry("/a/f.txt").unwrap().is_none());
        let moved = db.get_entry("/b/f.txt").unwrap().unwrap();
        assert_eq!(moved.parent_path, "/b");
    }
}
