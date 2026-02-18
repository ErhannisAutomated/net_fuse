pub mod keys;

use std::path::{Path, PathBuf};

use clap::Parser;
use serde::Deserialize;

/// Config file (TOML) — all fields optional; CLI args take precedence.
/// Default location: `{config_dir}/net_fuse/config.toml`
/// (Linux: `~/.config/net_fuse/config.toml`)
#[derive(Debug, Default, Deserialize)]
pub struct ConfigFile {
    pub mount: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
    pub name: Option<String>,
    pub port: Option<u16>,
    pub allow_other: Option<bool>,
    pub cache_soft_limit: Option<u64>,
    pub cache_hard_limit: Option<u64>,
    pub cache_max_age: Option<u64>,
    pub eviction_interval: Option<u64>,
    pub web_port: Option<u16>,
    /// Propagate per-peer last-known file states transitively during full sync,
    /// enabling deletion inference across nodes that never directly connected.
    /// Disable to trade correctness (file resurrection) for smaller sync messages.
    pub propagate_peer_states: Option<bool>,
}

impl ConfigFile {
    fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(contents) => toml::from_str(&contents).unwrap_or_else(|e| {
                eprintln!("Warning: failed to parse config file {path:?}: {e}");
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }
}

/// NetFuse — distributed peer-to-peer FUSE filesystem.
#[derive(Parser, Debug)]
#[command(name = "net_fuse", about = "Distributed P2P FUSE filesystem")]
pub struct CliArgs {
    /// Mount point for the FUSE filesystem (can also be set in config file).
    #[arg(short, long)]
    pub mount: Option<PathBuf>,

    /// Path to config file (default: {config_dir}/net_fuse/config.toml).
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Data directory (default: platform-specific app data dir).
    #[arg(short, long)]
    pub data_dir: Option<PathBuf>,

    /// Node name (default: hostname).
    #[arg(short, long)]
    pub name: Option<String>,

    /// Port to listen on for QUIC connections.
    #[arg(short, long)]
    pub port: Option<u16>,

    /// Allow mounting over a non-empty directory / allow other users.
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub allow_other: Option<bool>,

    /// Soft cache size limit in bytes (evict old blobs above this).
    #[arg(long)]
    pub cache_soft_limit: Option<u64>,

    /// Hard cache size limit in bytes (evict unconditionally above this).
    #[arg(long)]
    pub cache_hard_limit: Option<u64>,

    /// Maximum blob age in seconds for soft eviction (default 7 days).
    #[arg(long)]
    pub cache_max_age: Option<u64>,

    /// Interval in seconds between eviction cycles (default 5 min).
    #[arg(long)]
    pub eviction_interval: Option<u64>,

    /// Port for the HTTPS web interface.
    #[arg(long)]
    pub web_port: Option<u16>,

    /// Propagate peer sync state transitively to enable deletion inference across
    /// nodes that never directly connected. Default: true.
    /// Set to false if sync message size is a concern (risks file resurrection).
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub propagate_peer_states: Option<bool>,
}

/// Resolved application configuration.
pub struct AppConfig {
    pub mount_point: PathBuf,
    pub data_dir: PathBuf,
    pub blobs_dir: PathBuf,
    pub db_path: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub node_name: String,
    pub port: u16,
    pub allow_other: bool,
    pub cache_soft_limit: u64,
    pub cache_hard_limit: u64,
    pub cache_max_age_secs: u64,
    pub eviction_interval_secs: u64,
    pub web_port: u16,
    pub propagate_peer_states: bool,
}

impl AppConfig {
    pub fn from_args(args: &CliArgs) -> anyhow::Result<Self> {
        // Determine config file path and load it
        let config_path = args.config.clone().or_else(|| {
            directories::ProjectDirs::from("", "", "net_fuse")
                .map(|p| p.config_dir().join("config.toml"))
        });
        let cfg = config_path
            .as_deref()
            .map(ConfigFile::load)
            .unwrap_or_default();

        // Resolve mount point (CLI > config file — required from one of them)
        let mount_point = args
            .mount
            .clone()
            .or(cfg.mount)
            .ok_or_else(|| anyhow::anyhow!(
                "Mount point is required. Pass --mount <path> or set `mount` in config file."
            ))?;

        // Resolve data directory (CLI > config > platform default)
        let data_dir = args
            .data_dir
            .clone()
            .or(cfg.data_dir)
            .or_else(|| {
                directories::ProjectDirs::from("", "", "net_fuse")
                    .map(|p| p.data_dir().to_path_buf())
            })
            .ok_or_else(|| anyhow::anyhow!("Cannot determine data directory"))?;

        let blobs_dir = data_dir.join("blobs");
        let db_path = data_dir.join("metadata.db");
        let cert_path = data_dir.join("node_cert.der");
        let key_path = data_dir.join("node_key.der");

        let node_name = args.name.clone().or(cfg.name).unwrap_or_else(|| {
            hostname::get().map_or_else(
                |_| "unknown".to_string(),
                |h| h.to_string_lossy().to_string(),
            )
        });

        Ok(Self {
            mount_point,
            data_dir,
            blobs_dir,
            db_path,
            cert_path,
            key_path,
            node_name,
            port: args.port.or(cfg.port).unwrap_or(4433),
            allow_other: args.allow_other.or(cfg.allow_other).unwrap_or(false),
            cache_soft_limit: args
                .cache_soft_limit
                .or(cfg.cache_soft_limit)
                .unwrap_or(5_368_709_120),
            cache_hard_limit: args
                .cache_hard_limit
                .or(cfg.cache_hard_limit)
                .unwrap_or(10_737_418_240),
            cache_max_age_secs: args
                .cache_max_age
                .or(cfg.cache_max_age)
                .unwrap_or(604_800),
            eviction_interval_secs: args
                .eviction_interval
                .or(cfg.eviction_interval)
                .unwrap_or(300),
            web_port: args.web_port.or(cfg.web_port).unwrap_or(8443),
            propagate_peer_states: args
                .propagate_peer_states
                .or(cfg.propagate_peer_states)
                .unwrap_or(true),
        })
    }

    /// Ensure all required directories exist.
    pub fn ensure_dirs(&self) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.data_dir)?;
        std::fs::create_dir_all(&self.blobs_dir)?;
        std::fs::create_dir_all(&self.mount_point)?;
        Ok(())
    }
}
