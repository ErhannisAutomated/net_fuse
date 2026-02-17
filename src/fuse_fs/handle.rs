use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

/// Tracks open file handles and their associated temp files (for writes).
pub struct HandleTable {
    handles: HashMap<u64, HandleInfo>,
    next_fh: u64,
}

pub struct HandleInfo {
    pub path: String,
    pub temp_path: Option<PathBuf>,
    pub temp_file: Option<File>,
    pub writable: bool,
    /// True if data has been written since the last flush/finalization.
    pub dirty: bool,
    /// Current file size (tracks max offset + bytes_written for writable handles).
    pub current_size: u64,
}

impl HandleTable {
    pub fn new() -> Self {
        Self {
            handles: HashMap::new(),
            next_fh: 1,
        }
    }

    /// Allocate a new file handle for reading.
    pub fn open_read(&mut self, path: String) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        self.handles.insert(
            fh,
            HandleInfo {
                path,
                temp_path: None,
                temp_file: None,
                writable: false,
                dirty: false,
                current_size: 0,
            },
        );
        fh
    }

    /// Allocate a new file handle for writing with a temp file.
    pub fn open_write(&mut self, path: String, temp_path: PathBuf, temp_file: File) -> u64 {
        let fh = self.next_fh;
        self.next_fh += 1;
        self.handles.insert(
            fh,
            HandleInfo {
                path,
                temp_path: Some(temp_path),
                temp_file: Some(temp_file),
                writable: true,
                dirty: true,
                current_size: 0,
            },
        );
        fh
    }

    /// Get a handle's info.
    pub fn get(&self, fh: u64) -> Option<&HandleInfo> {
        self.handles.get(&fh)
    }

    /// Get a mutable reference to a handle's info.
    pub fn get_mut(&mut self, fh: u64) -> Option<&mut HandleInfo> {
        self.handles.get_mut(&fh)
    }

    /// Remove and return a handle.
    pub fn release(&mut self, fh: u64) -> Option<HandleInfo> {
        self.handles.remove(&fh)
    }

    /// Truncate all writable temp files for a given path to `new_size`.
    /// Used when setattr(size=...) arrives without a file handle.
    pub fn truncate_by_path(&mut self, path: &str, new_size: u64) {
        for handle in self.handles.values_mut() {
            if handle.writable && handle.path == path {
                if let Some(ref mut f) = handle.temp_file {
                    let _ = f.set_len(new_size);
                }
                handle.current_size = new_size;
                handle.dirty = true;
            }
        }
    }

    /// Iterate over all handles mutably.
    pub fn handles_iter_mut(&mut self) -> impl Iterator<Item = &mut HandleInfo> {
        self.handles.values_mut()
    }

    /// Get the current writable size for a path (if any handle is writing to it).
    /// Returns the maximum current_size across all writable handles for this path.
    pub fn writable_size(&self, path: &str) -> Option<u64> {
        let mut max_size: Option<u64> = None;
        for handle in self.handles.values() {
            if handle.writable && handle.path == path {
                let s = handle.current_size;
                max_size = Some(max_size.map_or(s, |m: u64| m.max(s)));
            }
        }
        max_size
    }
}

impl HandleInfo {
    /// Write data at the given offset in the temp file.
    pub fn write_at(&mut self, offset: i64, data: &[u8]) -> std::io::Result<usize> {
        if let Some(ref mut file) = self.temp_file {
            file.seek(SeekFrom::Start(offset as u64))?;
            let n = file.write(data)?;
            self.dirty = true;
            let end = offset as u64 + n as u64;
            if end > self.current_size {
                self.current_size = end;
            }
            Ok(n)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "no temp file for writing",
            ))
        }
    }

    /// Read data from the temp file at offset (for read-after-write).
    pub fn read_at(&mut self, offset: i64, size: usize) -> std::io::Result<Vec<u8>> {
        if let Some(ref mut file) = self.temp_file {
            file.seek(SeekFrom::Start(offset as u64))?;
            let mut buf = vec![0u8; size];
            let n = file.read(&mut buf)?;
            buf.truncate(n);
            Ok(buf)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "no temp file for reading",
            ))
        }
    }
}
