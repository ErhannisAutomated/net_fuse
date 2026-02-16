use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use fuser::MountOption;
use tracing::info;

use net_fuse::config::keys::NodeIdentity;
use net_fuse::config::{AppConfig, CliArgs};
use net_fuse::fuse_fs::NetFuseFS;
use net_fuse::metadata::MetadataDb;
use net_fuse::net::discovery::Discovery;
use net_fuse::net::peer_manager::PeerManager;
use net_fuse::net::transport::Transport;
use net_fuse::store::BlobStore;
use net_fuse::sync::SyncEngine;

#[tokio::main]
async fn main() -> Result<()> {
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

    // --- Phase 2+3: Networking & Sync ---

    // Load or generate TLS identity
    let identity = NodeIdentity::load_or_generate(
        &config.cert_path,
        &config.key_path,
        &config.node_name,
    )?;
    let server_config = identity.build_server_config()?;
    let client_config = identity.build_client_config()?;
    info!("TLS identity loaded");

    // Create channels for Transport -> SyncEngine communication
    let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(256);
    let (peer_connected_tx, peer_connected_rx) = tokio::sync::mpsc::channel(32);

    // Create QUIC transport
    let bind_addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let transport = Arc::new(
        Transport::new(
            bind_addr,
            node_id,
            config.node_name.clone(),
            server_config,
            client_config,
            incoming_tx,
            peer_connected_tx,
            store.clone(),
        )
        .await?,
    );
    info!("QUIC transport listening on {}", transport.local_addr()?);

    // Start accepting incoming connections
    let (connected_tx, mut connected_rx) = tokio::sync::mpsc::channel(32);
    tokio::spawn(transport.clone().accept_loop(connected_tx));

    // Log incoming peer connections
    tokio::spawn(async move {
        while let Some((peer_id, peer_name)) = connected_rx.recv().await {
            info!(%peer_id, %peer_name, "Peer connected (incoming)");
        }
    });

    // Start mDNS discovery
    let discovery = Discovery::new(node_id, &config.node_name, config.port)
        .context("mDNS discovery setup")?;
    let discovered_rx = discovery.browse()
        .context("mDNS browse")?;

    // Start peer manager (handles mDNS discoveries -> outgoing connections)
    let peer_mgr = PeerManager::new(transport.clone());
    tokio::spawn(async move {
        peer_mgr.handle_discoveries(discovered_rx).await;
    });

    // --- Phase 3: Sync Engine ---

    // Create the FUSE -> SyncEngine channel
    let (sync_tx, sync_rx) = tokio::sync::mpsc::unbounded_channel();

    // Start the sync engine
    let sync_engine = SyncEngine::new(
        db.clone(),
        transport.clone(),
        sync_rx,
        incoming_rx,
        peer_connected_rx,
    );
    tokio::spawn(sync_engine.run());

    // --- Mount FUSE filesystem ---

    let rt_handle = tokio::runtime::Handle::current();
    let fs = NetFuseFS::new(db, store, Some(sync_tx), Some(transport.clone()), Some(rt_handle));

    let mut options = vec![
        MountOption::FSName("net_fuse".to_string()),
        MountOption::DefaultPermissions,
    ];
    if config.allow_other {
        options.push(MountOption::AllowOther);
        options.push(MountOption::AutoUnmount);
    }

    info!("Mounting at {:?}", config.mount_point);

    // spawn_mount2 runs FUSE in a background thread, returns a session guard
    let _session = fuser::spawn_mount2(fs, &config.mount_point, &options)
        .context(format!("FUSE mount at {:?}", config.mount_point))?;

    // Wait for Ctrl-C
    tokio::signal::ctrl_c().await?;

    info!("Shutting down...");
    drop(_session);
    discovery.shutdown()?;

    info!("Goodbye.");
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
    let conn = rusqlite::Connection::open(db_path)?;
    net_fuse::metadata::schema::init_schema(&conn)?;
    conn.execute(
        "INSERT OR REPLACE INTO local_config (key, value) VALUES ('node_id', ?1)",
        rusqlite::params![id.to_string()],
    )?;
    Ok(id)
}
