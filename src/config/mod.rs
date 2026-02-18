pub mod keys;

use std::path::PathBuf;

use clap::Parser;

/// NetFuse — distributed peer-to-peer FUSE filesystem.
#[derive(Parser, Debug)]
#[command(name = "net_fuse", about = "Distributed P2P FUSE filesystem")]
pub struct CliArgs {
    /// Mount point for the FUSE filesystem.
    #[arg(short, long)]
    pub mount: PathBuf,

    /// Data directory (default: platform-specific app data dir).
    #[arg(short, long)]
    pub data_dir: Option<PathBuf>,

    /// Node name (default: hostname).
    #[arg(short, long)]
    pub name: Option<String>,

    /// Port to listen on for QUIC connections.
    #[arg(short, long, default_value = "4433")]
    pub port: u16,

    /// Allow mounting over a non-empty directory.
    #[arg(long, default_value_t = false)]
    pub allow_other: bool,

    /// Soft cache size limit in bytes (evict old blobs above this).
    #[arg(long, default_value_t = 5_368_709_120)]
    pub cache_soft_limit: u64,

    /// Hard cache size limit in bytes (evict unconditionally above this).
    #[arg(long, default_value_t = 10_737_418_240)]
    pub cache_hard_limit: u64,

    /// Maximum blob age in seconds for soft eviction (default 7 days).
    #[arg(long, default_value_t = 604_800)]
    pub cache_max_age: u64,

    /// Interval in seconds between eviction cycles (default 5 min).
    #[arg(long, default_value_t = 300)]
    pub eviction_interval: u64,

    /// Port for the HTTPS web interface.
    #[arg(long, default_value_t = 8443)]
    pub web_port: u16,
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
}

impl AppConfig {
    pub fn from_args(args: &CliArgs) -> anyhow::Result<Self> {
        let data_dir = match &args.data_dir {
            Some(d) => d.clone(),
            None => {
                let proj_dirs = directories::ProjectDirs::from("", "", "net_fuse")
                    .ok_or_else(|| anyhow::anyhow!("Cannot determine data directory"))?;
                proj_dirs.data_dir().to_path_buf()
            }
        };

        let blobs_dir = data_dir.join("blobs");
        let db_path = data_dir.join("metadata.db");
        let cert_path = data_dir.join("node_cert.der");
        let key_path = data_dir.join("node_key.der");

        let node_name = args
            .name
            .clone()
            .unwrap_or_else(|| hostname::get().map_or_else(
                |_| "unknown".to_string(),
                |h| h.to_string_lossy().to_string(),
            ));

        Ok(Self {
            mount_point: args.mount.clone(),
            data_dir,
            blobs_dir,
            db_path,
            cert_path,
            key_path,
            node_name,
            port: args.port,
            allow_other: args.allow_other,
            cache_soft_limit: args.cache_soft_limit,
            cache_hard_limit: args.cache_hard_limit,
            cache_max_age_secs: args.cache_max_age,
            eviction_interval_secs: args.eviction_interval,
            web_port: args.web_port,
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
