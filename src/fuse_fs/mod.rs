pub mod handle;
pub mod inode;

use std::ffi::OsStr;
use std::io::{Seek, SeekFrom, Write};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request,
};
use parking_lot::Mutex;
use tracing::{debug, error, warn};

use crate::metadata::types::{EntryKind, FileEntry, Timestamp, VectorClock};
use crate::metadata::MetadataDb;
use crate::store::BlobStore;
use crate::sync::SyncEvent;
use handle::HandleTable;
use inode::InodeMap;

const TTL: Duration = Duration::from_secs(1);
const BLOCK_SIZE: u32 = 512;

/// The main FUSE filesystem struct.
pub struct NetFuseFS {
    db: Arc<MetadataDb>,
    store: Arc<BlobStore>,
    inodes: Mutex<InodeMap>,
    handles: Mutex<HandleTable>,
    sync_tx: Option<tokio::sync::mpsc::UnboundedSender<SyncEvent>>,
    uid: u32,
    gid: u32,
}

impl NetFuseFS {
    pub fn new(
        db: Arc<MetadataDb>,
        store: Arc<BlobStore>,
        sync_tx: Option<tokio::sync::mpsc::UnboundedSender<SyncEvent>>,
    ) -> Self {
        let mut inode_map = InodeMap::new();
        // Rebuild inode map from existing DB entries
        if let Ok(paths) = db.all_paths() {
            inode_map.rebuild(&paths);
        }

        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        Self {
            db,
            store,
            inodes: Mutex::new(inode_map),
            handles: Mutex::new(HandleTable::new()),
            sync_tx,
            uid,
            gid,
        }
    }

    /// Send a sync event (fire-and-forget).
    fn send_sync(&self, event: SyncEvent) {
        if let Some(ref tx) = self.sync_tx {
            if let Err(e) = tx.send(event) {
                warn!("Failed to send sync event: {}", e);
            }
        }
    }

    fn entry_to_attr(&self, entry: &FileEntry, ino: u64) -> FileAttr {
        let kind = match entry.kind {
            EntryKind::File => FileType::RegularFile,
            EntryKind::Directory => FileType::Directory,
            EntryKind::Symlink => FileType::Symlink,
        };

        let nlink = if entry.kind == EntryKind::Directory {
            2
        } else {
            1
        };

        let mtime = entry.mtime.to_system_time();
        let ctime = entry.ctime.to_system_time();

        FileAttr {
            ino,
            size: entry.size,
            blocks: (entry.size + BLOCK_SIZE as u64 - 1) / BLOCK_SIZE as u64,
            atime: mtime,
            mtime,
            ctime,
            crtime: ctime,
            kind,
            perm: entry.permissions as u16,
            nlink,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: BLOCK_SIZE,
            flags: 0,
        }
    }

    /// Build a full path from parent inode + child name.
    fn child_path(&self, parent_ino: u64, name: &OsStr) -> Option<String> {
        let inodes = self.inodes.lock();
        let parent_path = inodes.get_path(parent_ino)?;
        let name = name.to_str()?;
        if parent_path == "/" {
            Some(format!("/{}", name))
        } else {
            Some(format!("{}/{}", parent_path, name))
        }
    }

    /// Get the parent path of a given path.
    fn parent_of(path: &str) -> &str {
        if path == "/" {
            return "";
        }
        match path.rfind('/') {
            Some(0) => "/",
            Some(i) => &path[..i],
            None => "/",
        }
    }
}

impl Filesystem for NetFuseFS {
    fn init(
        &mut self,
        _req: &Request<'_>,
        _config: &mut fuser::KernelConfig,
    ) -> std::result::Result<(), libc::c_int> {
        debug!("FUSE init");
        Ok(())
    }

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let Some(path) = self.child_path(parent, name) else {
            reply.error(libc::ENOENT);
            return;
        };

        match self.db.get_entry(&path) {
            Ok(Some(entry)) => {
                let ino = self.inodes.lock().get_or_insert(&path);
                let attr = self.entry_to_attr(&entry, ino);
                reply.entry(&TTL, &attr, 0);
            }
            Ok(None) => reply.error(libc::ENOENT),
            Err(e) => {
                error!("lookup error: {}", e);
                reply.error(libc::EIO);
            }
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let inodes = self.inodes.lock();
        let Some(path) = inodes.get_path(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        let path = path.to_string();
        drop(inodes);

        match self.db.get_entry(&path) {
            Ok(Some(entry)) => {
                let attr = self.entry_to_attr(&entry, ino);
                reply.attr(&TTL, &attr);
            }
            Ok(None) => reply.error(libc::ENOENT),
            Err(e) => {
                error!("getattr error: {}", e);
                reply.error(libc::EIO);
            }
        }
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let inodes = self.inodes.lock();
        let Some(path) = inodes.get_path(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        let path = path.to_string();
        drop(inodes);

        let Ok(Some(mut entry)) = self.db.get_entry(&path) else {
            reply.error(libc::ENOENT);
            return;
        };

        if let Some(mode) = mode {
            entry.permissions = mode;
        }

        if let Some(new_mtime) = mtime {
            entry.mtime = match new_mtime {
                fuser::TimeOrNow::SpecificTime(t) => {
                    let dur = t.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
                    Timestamp {
                        secs: dur.as_secs() as i64,
                        nanos: dur.subsec_nanos(),
                    }
                }
                fuser::TimeOrNow::Now => Timestamp::now(),
            };
        }

        // Handle truncation
        if let Some(new_size) = size {
            if new_size == 0 && entry.kind == EntryKind::File {
                entry.size = 0;
                entry.hash = None;
                entry.mtime = Timestamp::now();
            } else if let Some(fh_val) = fh {
                // Truncate via temp file
                let mut handles = self.handles.lock();
                if let Some(handle) = handles.get_mut(fh_val) {
                    if let Some(ref mut f) = handle.temp_file {
                        let _ = f.set_len(new_size);
                    }
                }
                entry.size = new_size;
            } else {
                entry.size = new_size;
            }
        }

        entry.vclock.increment(self.db.node_id());

        if let Err(e) = self.db.upsert_entry(&entry) {
            error!("setattr upsert error: {}", e);
            reply.error(libc::EIO);
            return;
        }

        self.send_sync(SyncEvent::FileUpdated(entry.clone()));

        let attr = self.entry_to_attr(&entry, ino);
        reply.attr(&TTL, &attr);
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let inodes = self.inodes.lock();
        let Some(path) = inodes.get_path(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        let path = path.to_string();
        drop(inodes);

        let children = match self.db.list_children(&path) {
            Ok(c) => c,
            Err(e) => {
                error!("readdir error: {}", e);
                reply.error(libc::EIO);
                return;
            }
        };

        let mut entries: Vec<(u64, FileType, String)> = Vec::new();
        entries.push((ino, FileType::Directory, ".".to_string()));

        // Parent inode
        let parent_ino = if path == "/" {
            1
        } else {
            let parent = Self::parent_of(&path);
            self.inodes.lock().get_ino(parent).unwrap_or(1)
        };
        entries.push((parent_ino, FileType::Directory, "..".to_string()));

        for child in &children {
            let child_ino = self.inodes.lock().get_or_insert(&child.path);
            let ft = match child.kind {
                EntryKind::File => FileType::RegularFile,
                EntryKind::Directory => FileType::Directory,
                EntryKind::Symlink => FileType::Symlink,
            };
            let name = child
                .path
                .rsplit('/')
                .next()
                .unwrap_or(&child.path)
                .to_string();
            entries.push((child_ino, ft, name));
        }

        for (i, (ino, ft, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*ino, (i + 1) as i64, *ft, name) {
                break;
            }
        }
        reply.ok();
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let Some(path) = self.child_path(parent, name) else {
            reply.error(libc::EINVAL);
            return;
        };

        let parent_path = {
            let inodes = self.inodes.lock();
            inodes.get_path(parent).map(|p| p.to_string())
        };
        let Some(parent_path) = parent_path else {
            reply.error(libc::ENOENT);
            return;
        };

        let mut entry = FileEntry::new_dir(path.clone(), parent_path, self.db.node_id());
        entry.permissions = mode;

        if let Err(e) = self.db.upsert_entry(&entry) {
            error!("mkdir error: {}", e);
            reply.error(libc::EIO);
            return;
        }

        self.send_sync(SyncEvent::DirCreated(entry.clone()));

        let ino = self.inodes.lock().get_or_insert(&path);
        let attr = self.entry_to_attr(&entry, ino);
        reply.entry(&TTL, &attr, 0);
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let Some(path) = self.child_path(parent, name) else {
            reply.error(libc::EINVAL);
            return;
        };

        let parent_path = {
            let inodes = self.inodes.lock();
            inodes.get_path(parent).map(|p| p.to_string())
        };
        let Some(parent_path) = parent_path else {
            reply.error(libc::ENOENT);
            return;
        };

        // Create temp file for writes
        let (temp_path, temp_file) = match self.store.create_temp() {
            Ok(tf) => tf,
            Err(e) => {
                error!("create temp error: {}", e);
                reply.error(libc::EIO);
                return;
            }
        };

        // Create an empty file entry in the DB
        let empty_hash = crate::sha256(b"");
        let mut entry =
            FileEntry::new_file(path.clone(), parent_path, empty_hash, 0, self.db.node_id());
        entry.permissions = mode;

        if let Err(e) = self.db.upsert_entry(&entry) {
            error!("create upsert error: {}", e);
            reply.error(libc::EIO);
            return;
        }

        let ino = self.inodes.lock().get_or_insert(&path);
        let fh = self
            .handles
            .lock()
            .open_write(path, temp_path, temp_file);
        let attr = self.entry_to_attr(&entry, ino);
        reply.created(&TTL, &attr, 0, fh, 0);
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let inodes = self.inodes.lock();
        let Some(path) = inodes.get_path(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        let path = path.to_string();
        drop(inodes);

        let writable = (flags & libc::O_ACCMODE) != libc::O_RDONLY;
        let truncate = (flags & libc::O_TRUNC) != 0;

        if writable {
            // Create a temp file and pre-populate with existing content
            let (temp_path, mut temp_file) = match self.store.create_temp() {
                Ok(tf) => tf,
                Err(e) => {
                    error!("open temp error: {}", e);
                    reply.error(libc::EIO);
                    return;
                }
            };

            // Copy existing blob content to temp file unless O_TRUNC is set
            if !truncate {
                if let Ok(Some(entry)) = self.db.get_entry(&path) {
                    if let Some(hash) = entry.hash {
                        if let Ok(data) = self.store.get(&hash) {
                            let _ = temp_file.write_all(&data);
                            let _ = temp_file.seek(SeekFrom::Start(0));
                        }
                    }
                }
            }

            let fh = self.handles.lock().open_write(path, temp_path, temp_file);
            reply.opened(fh, 0);
        } else {
            let fh = self.handles.lock().open_read(path);
            reply.opened(fh, 0);
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let mut handles = self.handles.lock();
        let Some(handle) = handles.get_mut(fh) else {
            reply.error(libc::EBADF);
            return;
        };

        match handle.write_at(offset, data) {
            Ok(written) => reply.written(written as u32),
            Err(e) => {
                error!("write error: {}", e);
                reply.error(libc::EIO);
            }
        }
    }

    fn flush(&mut self, _req: &Request<'_>, _ino: u64, fh: u64, _lock: u64, reply: ReplyEmpty) {
        let mut handles = self.handles.lock();
        if let Some(handle) = handles.get_mut(fh) {
            if let Some(ref mut f) = handle.temp_file {
                let _ = f.flush();
            }
        }
        reply.ok();
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let handle_info = self.handles.lock().release(fh);
        let Some(handle_info) = handle_info else {
            reply.ok();
            return;
        };

        if !handle_info.writable {
            reply.ok();
            return;
        }

        // Finalize the temp file: hash it, store the blob, update the entry
        let Some(temp_path) = handle_info.temp_path else {
            reply.ok();
            return;
        };
        // Drop the file handle before finalization
        drop(handle_info.temp_file);

        let (hash, size) = match self.store.finalize_temp(&temp_path) {
            Ok(hs) => hs,
            Err(e) => {
                error!("release finalize error: {}", e);
                reply.error(libc::EIO);
                return;
            }
        };

        let path = handle_info.path;

        // Update the DB entry
        match self.db.get_entry(&path) {
            Ok(Some(mut entry)) => {
                // Deref old blob if different
                if let Some(old_hash) = entry.hash {
                    if old_hash != hash {
                        let _ = self.db.deref_blob(&old_hash);
                    }
                }

                entry.hash = Some(hash);
                entry.size = size;
                entry.mtime = Timestamp::now();
                entry.vclock.increment(self.db.node_id());

                if let Err(e) = self.db.upsert_entry(&entry) {
                    error!("release upsert error: {}", e);
                    reply.error(libc::EIO);
                    return;
                }

                self.send_sync(SyncEvent::FileUpdated(entry.clone()));

                // Register the blob
                let blob_path = format!("{}/{}", &hex::encode(&hash)[..2], hex::encode(&hash));
                let _ = self.db.register_blob(&hash, size, &blob_path);
            }
            Ok(None) => {
                warn!("release: entry not found for path {}", path);
            }
            Err(e) => {
                error!("release get_entry error: {}", e);
                reply.error(libc::EIO);
                return;
            }
        }

        reply.ok();
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        // If there's an open writable handle, read from temp file
        {
            let mut handles = self.handles.lock();
            if let Some(handle) = handles.get_mut(fh) {
                if handle.writable {
                    match handle.read_at(offset, size as usize) {
                        Ok(data) => {
                            reply.data(&data);
                            return;
                        }
                        Err(e) => {
                            error!("read from temp error: {}", e);
                            reply.error(libc::EIO);
                            return;
                        }
                    }
                }
            }
        }

        let inodes = self.inodes.lock();
        let Some(path) = inodes.get_path(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        let path = path.to_string();
        drop(inodes);

        let entry = match self.db.get_entry(&path) {
            Ok(Some(e)) => e,
            Ok(None) => {
                reply.error(libc::ENOENT);
                return;
            }
            Err(e) => {
                error!("read get_entry error: {}", e);
                reply.error(libc::EIO);
                return;
            }
        };

        let Some(hash) = entry.hash else {
            // No blob (empty file)
            reply.data(&[]);
            return;
        };

        // Try to read from local store
        match self.store.get(&hash) {
            Ok(data) => {
                let _ = self.db.touch_blob(&hash);
                let start = offset as usize;
                if start >= data.len() {
                    reply.data(&[]);
                } else {
                    let end = (start + size as usize).min(data.len());
                    reply.data(&data[start..end]);
                }
            }
            Err(_) => {
                // Phase 1: no network fetch, return EIO
                warn!("blob not found locally: {}", hex::encode(hash));
                reply.error(libc::EIO);
            }
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(path) = self.child_path(parent, name) else {
            reply.error(libc::ENOENT);
            return;
        };

        // Get entry to deref its blob and capture vclock for sync
        let mut delete_vclock = VectorClock::new();
        if let Ok(Some(entry)) = self.db.get_entry(&path) {
            delete_vclock = entry.vclock.clone();
            delete_vclock.increment(self.db.node_id());
            if let Some(hash) = entry.hash {
                let _ = self.db.deref_blob(&hash);
            }
        }

        if let Err(e) = self.db.delete_entry(&path) {
            error!("unlink error: {}", e);
            reply.error(libc::EIO);
            return;
        }

        self.send_sync(SyncEvent::FileDeleted {
            path: path.clone(),
            vclock: delete_vclock,
            origin_node: self.db.node_id(),
        });

        self.inodes.lock().remove_path(&path);
        reply.ok();
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(path) = self.child_path(parent, name) else {
            reply.error(libc::ENOENT);
            return;
        };

        // Check if directory is empty
        match self.db.list_children(&path) {
            Ok(children) if !children.is_empty() => {
                reply.error(libc::ENOTEMPTY);
                return;
            }
            Err(e) => {
                error!("rmdir list error: {}", e);
                reply.error(libc::EIO);
                return;
            }
            _ => {}
        }

        // Capture vclock before deleting
        let mut delete_vclock = VectorClock::new();
        if let Ok(Some(entry)) = self.db.get_entry(&path) {
            delete_vclock = entry.vclock.clone();
            delete_vclock.increment(self.db.node_id());
        }

        if let Err(e) = self.db.delete_entry(&path) {
            error!("rmdir delete error: {}", e);
            reply.error(libc::EIO);
            return;
        }

        self.send_sync(SyncEvent::DirDeleted {
            path: path.clone(),
            vclock: delete_vclock,
            origin_node: self.db.node_id(),
        });

        self.inodes.lock().remove_path(&path);
        reply.ok();
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let Some(old_path) = self.child_path(parent, name) else {
            reply.error(libc::ENOENT);
            return;
        };
        let Some(new_path) = self.child_path(newparent, newname) else {
            reply.error(libc::EINVAL);
            return;
        };

        let new_parent = {
            let inodes = self.inodes.lock();
            inodes.get_path(newparent).map(|p| p.to_string())
        };
        let Some(new_parent) = new_parent else {
            reply.error(libc::ENOENT);
            return;
        };

        // If destination exists, remove it first
        if let Ok(Some(existing)) = self.db.get_entry(&new_path) {
            if existing.kind == EntryKind::Directory {
                // Check if empty
                if let Ok(children) = self.db.list_children(&new_path) {
                    if !children.is_empty() {
                        reply.error(libc::ENOTEMPTY);
                        return;
                    }
                }
            }
            if let Some(hash) = existing.hash {
                let _ = self.db.deref_blob(&hash);
            }
            let _ = self.db.delete_entry(&new_path);
            self.inodes.lock().remove_path(&new_path);
        }

        if let Err(e) = self.db.rename_entry(&old_path, &new_path, &new_parent) {
            error!("rename error: {}", e);
            reply.error(libc::EIO);
            return;
        }

        // Send sync event with the new entry
        if let Ok(Some(new_entry)) = self.db.get_entry(&new_path) {
            self.send_sync(SyncEvent::Renamed {
                old_path: old_path.clone(),
                new_entry,
            });
        }

        self.inodes.lock().rename(&old_path, &new_path);
        reply.ok();
    }
}
