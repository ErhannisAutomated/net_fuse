use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use fuser::MountOption;
use tracing::info;

use net_fuse::cache::CacheManager;
use net_fuse::config::keys::NodeIdentity;
use net_fuse::config::{AppConfig, CliArgs};
use net_fuse::fuse_fs::NetFuseFS;
use net_fuse::metadata::MetadataDb;
use net_fuse::net::discovery::Discovery;
use net_fuse::net::peer_auth::{AuthDecision, PeerAuth, PendingPeer};
use net_fuse::net::peer_manager::PeerManager;
use net_fuse::net::transport::Transport;
use net_fuse::net::web::WebServer;
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
    let identity = Arc::new(NodeIdentity::load_or_generate(
        &config.cert_path,
        &config.key_path,
        &config.node_name,
    )?);
    let server_config = identity.build_server_config()?;
    let client_config = identity.build_client_config()?;
    info!("TLS identity loaded");

    // Compute our certificate fingerprint and set up peer authorization
    let our_fingerprint = net_fuse::cert_fingerprint(&identity.cert_der);
    println!("Our fingerprint: SHA256:{our_fingerprint}");

    let (pending_tx, pending_rx) = tokio::sync::mpsc::unbounded_channel();
    let (approved_tx, approved_rx) = tokio::sync::mpsc::unbounded_channel();
    let peer_auth = Arc::new(PeerAuth::new(
        config.data_dir.join("peer_auth.json"),
        our_fingerprint,
        pending_tx,
    ));
    peer_auth.set_approved_notifier(approved_tx);

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
            peer_auth.clone(),
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
        peer_mgr.handle_discoveries(discovered_rx, approved_rx).await;
    });

    // --- Peer authorization UI tasks ---

    // Spawn stdin reader + prompt task for pending peer authorization
    let peer_auth_ui = peer_auth.clone();
    tokio::spawn(peer_auth_ui_task(pending_rx, peer_auth_ui));

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
        config.propagate_peer_states,
    );
    tokio::spawn(sync_engine.run());

    // --- Phase 6: Web Server ---

    let web_server = Arc::new(WebServer::new(
        db.clone(),
        store.clone(),
        peer_auth.clone(),
        sync_tx.clone(),
        node_id,
        identity.clone(),
    ));
    let web_port = config.web_port;
    tokio::spawn(async move {
        if let Err(e) = web_server.run(web_port).await {
            tracing::error!(error = %e, "Web server failed");
        }
    });
    println!("Web interface: https://localhost:{}", config.web_port);
    println!("Enroll at: https://localhost:{}/enroll", config.web_port);

    // --- Phase 5: Cache Eviction ---

    let cache_mgr = CacheManager::new(db.clone(), store.clone(), transport.clone(), &config);
    tokio::spawn(cache_mgr.run());

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

/// Background task that collects pending peers and prompts the user for decisions via stdin.
async fn peer_auth_ui_task(
    mut pending_rx: tokio::sync::mpsc::UnboundedReceiver<PendingPeer>,
    peer_auth: Arc<PeerAuth>,
) {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let mut pending: HashMap<String, PendingPeer> = HashMap::new();
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();

    let mut prompt_interval = tokio::time::interval(std::time::Duration::from_secs(10));
    prompt_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            // Collect newly pending peers
            peer = pending_rx.recv() => {
                match peer {
                    Some(p) => {
                        // Only add if not already decided
                        if !pending.contains_key(&p.fingerprint) {
                            let our_fp = peer_auth.our_fingerprint();
                            println!("\n--- New peer awaiting authorization ---");
                            println!("  Our fingerprint:  SHA256:{}", &our_fp[..16]);
                            println!("  Peer fingerprint: SHA256:{}", &p.fingerprint[..16]);
                            println!("  (w)hitelist | (s)ession-allow | (i)gnore-session | (b)lacklist");
                            print!("> ");
                            pending.insert(p.fingerprint.clone(), p);
                        }
                    }
                    None => break, // channel closed
                }
            }
            // Periodic prompt for any still-pending peers
            _ = prompt_interval.tick() => {
                // Remove peers that have been decided since they were added
                pending.retain(|fp, _| peer_auth.check(fp) == net_fuse::net::peer_auth::AuthResult::Pending);

                if !pending.is_empty() {
                    let our_fp = peer_auth.our_fingerprint();
                    println!("\n--- Pending peer authorization ({} peer(s)) ---", pending.len());
                    println!("  Our fingerprint:  SHA256:{}", &our_fp[..16]);
                    for p in pending.values() {
                        println!("  Peer fingerprint: SHA256:{}", &p.fingerprint[..16]);
                    }
                    println!("  (w)hitelist | (s)ession-allow | (i)gnore-session | (b)lacklist");
                    if pending.len() > 1 {
                        println!("  Prefix with fingerprint, e.g.: w a1b2");
                    }
                    print!("> ");
                }
            }
            // Read user input
            line = lines.next_line() => {
                match line {
                    Ok(Some(input)) => {
                        let input = input.trim().to_string();
                        if input.is_empty() {
                            continue;
                        }

                        let (cmd, prefix) = if input.len() > 1 {
                            let cmd = &input[..1];
                            let prefix = input[1..].trim().to_string();
                            (cmd.to_string(), if prefix.is_empty() { None } else { Some(prefix) })
                        } else {
                            (input.clone(), None)
                        };

                        let decision = match cmd.as_str() {
                            "w" => Some(AuthDecision::Whitelist),
                            "s" => Some(AuthDecision::SessionAllow),
                            "i" => Some(AuthDecision::SessionIgnore),
                            "b" => Some(AuthDecision::Blacklist),
                            _ => {
                                println!("Unknown command '{}'. Use w/s/i/b.", cmd);
                                None
                            }
                        };

                        if let Some(decision) = decision {
                            // Find the target peer
                            let target = if pending.len() == 1 && prefix.is_none() {
                                pending.keys().next().cloned()
                            } else if let Some(ref pfx) = prefix {
                                pending.keys().find(|fp| fp.starts_with(pfx.as_str())).cloned()
                            } else if pending.len() == 1 {
                                pending.keys().next().cloned()
                            } else {
                                println!("Multiple peers pending — specify fingerprint prefix, e.g.: w a1b2");
                                None
                            };

                            if let Some(fp) = target {
                                if let Some(p) = pending.remove(&fp) {
                                    peer_auth.apply_decision(&fp, &p.name, decision);
                                    println!("Decision applied for peer {:?}.", p.name);
                                }
                            } else if prefix.is_some() {
                                println!("No pending peer matching that prefix.");
                            }
                        }
                    }
                    Ok(None) => break, // EOF
                    Err(e) => {
                        tracing::warn!(error = %e, "Error reading stdin");
                        break;
                    }
                }
            }
        }
    }
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
