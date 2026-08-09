pub mod banner;
pub mod host;
pub mod port;

use std::net::Ipv4Addr;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
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
    // Producer and consumer run together: the producer holds the only senders
    // and blocks once the channel is full, so draining afterwards would hang on
    // any scan with more results than capacity.
    let (host_tx, mut host_rx) = mpsc::channel::<HostResult>(256);
    let sweeping = tokio::spawn(host::sweep(targets, config.timeout_ms, host_tx));

    let mut hosts = Vec::new();
    while let Some(h) = host_rx.recv().await {
        hosts.push(h);
    }
    let _ = sweeping.await;

    // --- port scan each live host ---
    let (port_tx, mut port_rx) = mpsc::channel::<PortResult>(1024);
    let scanned = Arc::new(AtomicUsize::new(0));

    let scanning = {
        let ports = config.ports.clone();
        let timeout_ms = config.timeout_ms;
        let ips: Vec<Ipv4Addr> = hosts.iter().map(|h| h.ip).collect();
        let scanned = Arc::clone(&scanned);
        tokio::spawn(async move {
            for ip in ips {
                port::scan(
                    ip,
                    ports.clone(),
                    timeout_ms,
                    port_tx.clone(),
                    Arc::clone(&scanned),
                )
                .await;
            }
        })
    };

    let mut ports = Vec::new();
    while let Some(p) = port_rx.recv().await {
        // attempt banner grab on each open port
        let banner = banner::grab(p.ip, p.port, config.timeout_ms).await;
        ports.push(PortResult { banner, ..p });
    }
    let _ = scanning.await;

    ScanResults { hosts, ports }
}
