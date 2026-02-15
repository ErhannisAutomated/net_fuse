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

    /// Allow mounting over a non-empty directory.
    #[arg(long, default_value_t = false)]
    pub allow_other: bool,
}

/// Resolved application configuration.
pub struct AppConfig {
    pub mount_point: PathBuf,
    pub data_dir: PathBuf,
    pub blobs_dir: PathBuf,
    pub db_path: PathBuf,
    pub node_name: String,
    pub allow_other: bool,
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
            node_name,
            allow_other: args.allow_other,
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
