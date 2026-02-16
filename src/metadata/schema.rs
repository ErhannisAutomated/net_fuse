use rusqlite::Connection;

/// Initialize the database schema.
pub fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;
    conn.execute_batch("PRAGMA busy_timeout=5000;")?;

    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS files (
            path TEXT PRIMARY KEY,
            parent_path TEXT NOT NULL,
            hash BLOB,
            size INTEGER NOT NULL DEFAULT 0,
            mtime_secs INTEGER NOT NULL,
            mtime_nanos INTEGER NOT NULL,
            ctime_secs INTEGER NOT NULL,
            ctime_nanos INTEGER NOT NULL,
            permissions INTEGER NOT NULL DEFAULT 420,
            kind INTEGER NOT NULL,
            vclock BLOB NOT NULL,
            origin_node BLOB NOT NULL,
            conflict_id BLOB
        );

        CREATE INDEX IF NOT EXISTS idx_files_parent ON files(parent_path);

        CREATE TABLE IF NOT EXISTS blobs (
            hash BLOB PRIMARY KEY,
            size INTEGER NOT NULL,
            local_path TEXT NOT NULL,
            last_accessed INTEGER NOT NULL,
            ref_count INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS peers (
            node_id BLOB PRIMARY KEY,
            public_key BLOB,
            name TEXT,
            last_seen INTEGER,
            trusted INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS blob_locations (
            hash BLOB NOT NULL,
            node_id BLOB NOT NULL,
            last_confirmed INTEGER NOT NULL,
            PRIMARY KEY (hash, node_id)
        );

        CREATE TABLE IF NOT EXISTS local_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        ",
    )?;

    // Migration: add `pinned` column to blobs (idempotent).
    let has_pinned: bool = conn
        .prepare("SELECT pinned FROM blobs LIMIT 0")
        .is_ok();
    if !has_pinned {
        conn.execute_batch("ALTER TABLE blobs ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0;")?;
    }

    Ok(())
}

/// Ensure the root directory entry exists.
pub fn ensure_root(conn: &Connection, node_id: uuid::Uuid) -> rusqlite::Result<()> {
    use crate::metadata::types::{EntryKind, Timestamp, VectorClock};

    let exists: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM files WHERE path = '/'",
        [],
        |row| row.get(0),
    )?;

    if !exists {
        let now = Timestamp::now();
        let mut vclock = VectorClock::new();
        vclock.increment(node_id);
        let vclock_bytes = vclock.serialize();

        conn.execute(
            "INSERT INTO files (path, parent_path, hash, size, mtime_secs, mtime_nanos,
             ctime_secs, ctime_nanos, permissions, kind, vclock, origin_node, conflict_id)
             VALUES (?1, ?2, NULL, 0, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL)",
            rusqlite::params![
                "/",
                "",
                now.secs,
                now.nanos,
                now.secs,
                now.nanos,
                0o755i64,
                EntryKind::Directory as u8,
                vclock_bytes,
                node_id.as_bytes().as_slice(),
            ],
        )?;
    }

    Ok(())
}
