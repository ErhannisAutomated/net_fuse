use std::net::SocketAddr;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use tokio::sync::mpsc;
use tracing::{debug, info};
use uuid::Uuid;

const SERVICE_TYPE: &str = "_netfuse._udp.local.";

/// A peer discovered via mDNS.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub node_id: Uuid,
    pub name: String,
    pub addr: SocketAddr,
}

/// mDNS service discovery: registers this node and browses for peers.
pub struct Discovery {
    daemon: ServiceDaemon,
    node_id: Uuid,
}

impl Discovery {
    /// Create a new discovery service, registering this node on the LAN.
    pub fn new(node_id: Uuid, node_name: &str, port: u16) -> anyhow::Result<Self> {
        let daemon = ServiceDaemon::new()?;

        // Instance name must be unique on the network
        let instance_name = format!("netfuse-{}", &node_id.to_string()[..8]);

        let host_name = format!(
            "{}.local.",
            hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "localhost".to_string())
        );

        let node_id_str = node_id.to_string();
        let properties = [
            ("node_id", node_id_str.as_str()),
            ("name", node_name),
        ];

        let service = ServiceInfo::new(
            SERVICE_TYPE,
            &instance_name,
            &host_name,
            "", // auto-detect IP
            port,
            &properties[..],
        )?
        .enable_addr_auto();

        daemon.register(service)?;
        info!("mDNS: registered as {}", instance_name);

        Ok(Self { daemon, node_id })
    }

    /// Start browsing for peers. Returns a channel that receives discovered peers.
    pub fn browse(&self) -> anyhow::Result<mpsc::Receiver<DiscoveredPeer>> {
        let receiver = self.daemon.browse(SERVICE_TYPE)?;
        let (tx, rx) = mpsc::channel(32);
        let my_id = self.node_id;

        // mdns-sd uses std channels, so we need a blocking bridge
        tokio::task::spawn_blocking(move || {
            while let Ok(event) = receiver.recv() {
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        // Extract node_id from properties
                        let node_id_str = match info.get_property_val_str("node_id") {
                            Some(s) => s.to_string(),
                            None => {
                                debug!("mDNS: resolved service without node_id property");
                                continue;
                            }
                        };
                        let Ok(node_id) = Uuid::parse_str(&node_id_str) else {
                            debug!("mDNS: invalid node_id in service: {}", node_id_str);
                            continue;
                        };

                        // Skip ourselves
                        if node_id == my_id {
                            continue;
                        }

                        let name = info
                            .get_property_val_str("name")
                            .unwrap_or("unknown")
                            .to_string();

                        // Get address — take the first available
                        let addrs = info.get_addresses();
                        let Some(ip) = addrs.iter().next() else {
                            debug!("mDNS: resolved service with no addresses");
                            continue;
                        };
                        let port = info.get_port();
                        let addr = SocketAddr::new(*ip, port);

                        info!(
                            %node_id, %name, %addr,
                            "mDNS: discovered peer"
                        );

                        if tx.blocking_send(DiscoveredPeer { node_id, name, addr }).is_err() {
                            break; // channel closed
                        }
                    }
                    ServiceEvent::ServiceRemoved(_type, name) => {
                        debug!("mDNS: service removed: {}", name);
                    }
                    _ => {}
                }
            }
        });

        Ok(rx)
    }

    /// Shut down the mDNS daemon (unregisters services).
    pub fn shutdown(self) -> anyhow::Result<()> {
        self.daemon.shutdown()?;
        Ok(())
    }
}
