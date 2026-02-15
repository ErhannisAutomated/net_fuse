use std::collections::HashMap;

/// Bidirectional inode <-> path map. Root is always inode 1.
pub struct InodeMap {
    path_to_ino: HashMap<String, u64>,
    ino_to_path: HashMap<u64, String>,
    next_ino: u64,
}

impl InodeMap {
    pub fn new() -> Self {
        let mut map = Self {
            path_to_ino: HashMap::new(),
            ino_to_path: HashMap::new(),
            next_ino: 2, // 1 is root
        };
        map.path_to_ino.insert("/".to_string(), 1);
        map.ino_to_path.insert(1, "/".to_string());
        map
    }

    /// Get the inode for a path, allocating a new one if needed.
    pub fn get_or_insert(&mut self, path: &str) -> u64 {
        if let Some(&ino) = self.path_to_ino.get(path) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.path_to_ino.insert(path.to_string(), ino);
        self.ino_to_path.insert(ino, path.to_string());
        ino
    }

    /// Look up the inode for a path without allocating.
    pub fn get_ino(&self, path: &str) -> Option<u64> {
        self.path_to_ino.get(path).copied()
    }

    /// Look up the path for an inode.
    pub fn get_path(&self, ino: u64) -> Option<&str> {
        self.ino_to_path.get(&ino).map(|s| s.as_str())
    }

    /// Remove a mapping.
    pub fn remove_path(&mut self, path: &str) {
        if let Some(ino) = self.path_to_ino.remove(path) {
            self.ino_to_path.remove(&ino);
        }
    }

    /// Rename: update mappings from old_path to new_path (and descendants).
    pub fn rename(&mut self, old_path: &str, new_path: &str) {
        // Collect paths to rename (old_path itself + descendants)
        let old_prefix = if old_path == "/" {
            "/".to_string()
        } else {
            format!("{}/", old_path)
        };

        let to_rename: Vec<(String, u64)> = self
            .path_to_ino
            .iter()
            .filter(|(p, _)| *p == old_path || p.starts_with(&old_prefix))
            .map(|(p, &ino)| (p.clone(), ino))
            .collect();

        let new_prefix = if new_path == "/" {
            "/".to_string()
        } else {
            format!("{}/", new_path)
        };

        for (path, ino) in to_rename {
            self.path_to_ino.remove(&path);
            let new = if path == old_path {
                new_path.to_string()
            } else {
                format!("{}{}", new_prefix, &path[old_prefix.len()..])
            };
            self.path_to_ino.insert(new.clone(), ino);
            self.ino_to_path.insert(ino, new);
        }
    }

    /// Rebuild the inode map from a list of paths.
    pub fn rebuild(&mut self, paths: &[String]) {
        self.path_to_ino.clear();
        self.ino_to_path.clear();
        self.next_ino = 2;

        // Root always exists
        self.path_to_ino.insert("/".to_string(), 1);
        self.ino_to_path.insert(1, "/".to_string());

        for path in paths {
            if path != "/" {
                self.get_or_insert(path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root() {
        let map = InodeMap::new();
        assert_eq!(map.get_ino("/"), Some(1));
        assert_eq!(map.get_path(1), Some("/"));
    }

    #[test]
    fn test_get_or_insert() {
        let mut map = InodeMap::new();
        let ino = map.get_or_insert("/test");
        assert_eq!(ino, 2);
        assert_eq!(map.get_or_insert("/test"), 2); // Same inode
        assert_eq!(map.get_or_insert("/other"), 3); // New inode
    }

    #[test]
    fn test_remove() {
        let mut map = InodeMap::new();
        map.get_or_insert("/test");
        map.remove_path("/test");
        assert_eq!(map.get_ino("/test"), None);
    }

    #[test]
    fn test_rename() {
        let mut map = InodeMap::new();
        let ino_dir = map.get_or_insert("/a");
        let ino_file = map.get_or_insert("/a/f.txt");

        map.rename("/a", "/b");

        assert_eq!(map.get_ino("/a"), None);
        assert_eq!(map.get_ino("/b"), Some(ino_dir));
        assert_eq!(map.get_ino("/a/f.txt"), None);
        assert_eq!(map.get_ino("/b/f.txt"), Some(ino_file));
    }

    #[test]
    fn test_rebuild() {
        let mut map = InodeMap::new();
        map.rebuild(&["/".to_string(), "/a".to_string(), "/a/b".to_string()]);
        assert_eq!(map.get_ino("/"), Some(1));
        assert!(map.get_ino("/a").is_some());
        assert!(map.get_ino("/a/b").is_some());
    }
}
