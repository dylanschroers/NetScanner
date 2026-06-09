pub mod banner;
pub mod host;
pub mod port;

use std::net::Ipv4Addr;
use tokio::sync::mpsc;

use crate::config::ScanConfig;
use port::PortResult;
use host::HostResult;

pub struct ScanResults {
    pub hosts: Vec<HostResult>,
    pub ports: Vec<PortResult>,
}

/// Run a full scan: host discovery followed by port scanning each live host.
/// Returns all discovered hosts and open ports.
pub async fn run(config: &ScanConfig, targets: Vec<Ipv4Addr>) -> ScanResults {
    // --- host discovery ---
    let (host_tx, mut host_rx) = mpsc::channel::<HostResult>(256);
    host::sweep(targets, config.timeout_ms, host_tx).await;

    let mut hosts = Vec::new();
    while let Ok(h) = host_rx.try_recv() {
        hosts.push(h);
    }

    // --- port scan each live host ---
    let (port_tx, mut port_rx) = mpsc::channel::<PortResult>(1024);

    for host in &hosts {
        port::scan(host.ip, config.ports.clone(), config.timeout_ms, port_tx.clone()).await;
    }
    drop(port_tx);

    let mut ports = Vec::new();
    while let Ok(p) = port_rx.try_recv() {
        // attempt banner grab on each open port
        let banner = banner::grab(p.ip, p.port, config.timeout_ms).await;
        ports.push(PortResult { banner, ..p });
    }

    ScanResults { hosts, ports }
}
