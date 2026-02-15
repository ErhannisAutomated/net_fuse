use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::BlobHash;

/// Vector clock for causal ordering of updates.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VectorClock {
    pub clocks: BTreeMap<uuid::Uuid, u64>,
}

impl VectorClock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the clock for the given node.
    pub fn increment(&mut self, node_id: uuid::Uuid) {
        let entry = self.clocks.entry(node_id).or_insert(0);
        *entry += 1;
    }

    /// Merge another vector clock into this one (element-wise max).
    pub fn merge(&mut self, other: &VectorClock) {
        for (&node_id, &count) in &other.clocks {
            let entry = self.clocks.entry(node_id).or_insert(0);
            *entry = (*entry).max(count);
        }
    }

    /// Returns the partial ordering between two vector clocks.
    /// - `Some(Less)` if self < other (other dominates)
    /// - `Some(Greater)` if self > other (self dominates)
    /// - `Some(Equal)` if identical
    /// - `None` if concurrent (neither dominates)
    pub fn partial_cmp(&self, other: &VectorClock) -> Option<std::cmp::Ordering> {
        let mut has_less = false;
        let mut has_greater = false;

        let all_keys: std::collections::BTreeSet<_> =
            self.clocks.keys().chain(other.clocks.keys()).collect();

        for key in all_keys {
            let a = self.clocks.get(key).copied().unwrap_or(0);
            let b = other.clocks.get(key).copied().unwrap_or(0);
            if a < b {
                has_less = true;
            }
            if a > b {
                has_greater = true;
            }
            if has_less && has_greater {
                return None; // Concurrent
            }
        }

        match (has_less, has_greater) {
            (false, false) => Some(std::cmp::Ordering::Equal),
            (true, false) => Some(std::cmp::Ordering::Less),
            (false, true) => Some(std::cmp::Ordering::Greater),
            (true, true) => None,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("VectorClock serialization failed")
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(data)
    }
}

/// Kind of filesystem entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EntryKind {
    File = 0,
    Directory = 1,
    Symlink = 2,
}

impl EntryKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::File),
            1 => Some(Self::Directory),
            2 => Some(Self::Symlink),
            _ => None,
        }
    }
}

/// Timestamp with second + nanosecond precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    pub secs: i64,
    pub nanos: u32,
}

impl Timestamp {
    pub fn now() -> Self {
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        Self {
            secs: dur.as_secs() as i64,
            nanos: dur.subsec_nanos(),
        }
    }

    pub fn to_system_time(self) -> SystemTime {
        if self.secs >= 0 {
            UNIX_EPOCH + Duration::new(self.secs as u64, self.nanos)
        } else {
            UNIX_EPOCH - Duration::new((-self.secs) as u64, self.nanos)
        }
    }
}

/// A file/directory entry in the metadata DB.
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: String,
    pub parent_path: String,
    pub hash: Option<BlobHash>,
    pub size: u64,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
    pub permissions: u32,
    pub kind: EntryKind,
    pub vclock: VectorClock,
    pub origin_node: uuid::Uuid,
    pub conflict_id: Option<uuid::Uuid>,
}

impl FileEntry {
    /// Create a new directory entry.
    pub fn new_dir(path: String, parent_path: String, node_id: uuid::Uuid) -> Self {
        let now = Timestamp::now();
        let mut vclock = VectorClock::new();
        vclock.increment(node_id);
        Self {
            path,
            parent_path,
            hash: None,
            size: 0,
            mtime: now,
            ctime: now,
            permissions: 0o755,
            kind: EntryKind::Directory,
            vclock,
            origin_node: node_id,
            conflict_id: None,
        }
    }

    /// Create a new file entry.
    pub fn new_file(
        path: String,
        parent_path: String,
        hash: BlobHash,
        size: u64,
        node_id: uuid::Uuid,
    ) -> Self {
        let now = Timestamp::now();
        let mut vclock = VectorClock::new();
        vclock.increment(node_id);
        Self {
            path,
            parent_path,
            hash: Some(hash),
            size,
            mtime: now,
            ctime: now,
            permissions: 0o644,
            kind: EntryKind::File,
            vclock,
            origin_node: node_id,
            conflict_id: None,
        }
    }
}

/// Record of a blob in the store.
#[derive(Debug, Clone)]
pub struct BlobRecord {
    pub hash: BlobHash,
    pub size: u64,
    pub local_path: String,
    pub last_accessed: i64,
    pub ref_count: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vclock_increment_and_compare() {
        let node_a = uuid::Uuid::new_v4();
        let node_b = uuid::Uuid::new_v4();

        let mut a = VectorClock::new();
        a.increment(node_a);

        let mut b = a.clone();
        b.increment(node_b);

        // a < b (b dominates)
        assert_eq!(a.partial_cmp(&b), Some(std::cmp::Ordering::Less));
        assert_eq!(b.partial_cmp(&a), Some(std::cmp::Ordering::Greater));
    }

    #[test]
    fn test_vclock_concurrent() {
        let node_a = uuid::Uuid::new_v4();
        let node_b = uuid::Uuid::new_v4();

        let mut a = VectorClock::new();
        a.increment(node_a);

        let mut b = VectorClock::new();
        b.increment(node_b);

        // Neither dominates
        assert_eq!(a.partial_cmp(&b), None);
    }

    #[test]
    fn test_vclock_merge() {
        let node_a = uuid::Uuid::new_v4();
        let node_b = uuid::Uuid::new_v4();

        let mut a = VectorClock::new();
        a.increment(node_a);
        a.increment(node_a);

        let mut b = VectorClock::new();
        b.increment(node_b);

        a.merge(&b);
        assert_eq!(a.clocks[&node_a], 2);
        assert_eq!(a.clocks[&node_b], 1);
    }

    #[test]
    fn test_vclock_equal() {
        let a = VectorClock::new();
        let b = VectorClock::new();
        assert_eq!(a.partial_cmp(&b), Some(std::cmp::Ordering::Equal));
    }

    #[test]
    fn test_vclock_serialization() {
        let node = uuid::Uuid::new_v4();
        let mut vc = VectorClock::new();
        vc.increment(node);
        vc.increment(node);

        let data = vc.serialize();
        let vc2 = VectorClock::deserialize(&data).unwrap();
        assert_eq!(vc, vc2);
    }
}
