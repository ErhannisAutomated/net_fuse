use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use fuser::MountOption;
use tracing::info;

use net_fuse::config::{AppConfig, CliArgs};
use net_fuse::fuse_fs::NetFuseFS;
use net_fuse::metadata::MetadataDb;
use net_fuse::store::BlobStore;

fn main() -> Result<()> {
    // Init logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = CliArgs::parse();
    let config = AppConfig::from_args(&args)?;
    config.ensure_dirs()?;

    // Load or generate node ID
    let node_id = load_or_create_node_id(&config)?;
    info!(node_id = %node_id, name = %config.node_name, "Starting NetFuse");

    // Open metadata DB
    let db = Arc::new(MetadataDb::open(&config.db_path, node_id)?);
    info!("Opened metadata database at {:?}", config.db_path);

    // Create blob store
    let store = Arc::new(BlobStore::new(config.blobs_dir.clone())?);
    info!("Blob store at {:?}", config.blobs_dir);

    // Create FUSE filesystem
    let fs = NetFuseFS::new(db, store);

    // Mount options
    let mut options = vec![
        MountOption::FSName("net_fuse".to_string()),
        MountOption::AutoUnmount,
        MountOption::DefaultPermissions,
    ];
    if config.allow_other {
        options.push(MountOption::AllowOther);
    }

    info!("Mounting at {:?}", config.mount_point);

    // Mount the filesystem (blocks until unmounted or Ctrl-C)
    fuser::mount2(fs, &config.mount_point, &options)?;

    info!("Unmounted. Goodbye.");
    Ok(())
}

/// Load the node ID from the database, or generate a new one.
fn load_or_create_node_id(config: &AppConfig) -> Result<uuid::Uuid> {
    let db_path = &config.db_path;

    if db_path.exists() {
        let conn = rusqlite::Connection::open(db_path)?;
        let result: std::result::Result<String, _> = conn.query_row(
            "SELECT value FROM local_config WHERE key = 'node_id'",
            [],
            |row| row.get(0),
        );
        if let Ok(id_str) = result {
            if let Ok(id) = uuid::Uuid::parse_str(&id_str) {
                return Ok(id);
            }
        }
    }

    // Generate a new node ID and store it
    let id = uuid::Uuid::new_v4();
    // The DB will be created by MetadataDb::open, but we need the ID first.
    // Store it after DB is created — we'll do it via a simple approach:
    // open db, init schema, store config.
    let conn = rusqlite::Connection::open(db_path)?;
    net_fuse::metadata::schema::init_schema(&conn)?;
    conn.execute(
        "INSERT OR REPLACE INTO local_config (key, value) VALUES ('node_id', ?1)",
        rusqlite::params![id.to_string()],
    )?;
    Ok(id)
}
