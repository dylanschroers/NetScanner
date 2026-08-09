use pnet::datalink::{self, NetworkInterface};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinSet;

use crate::packet::{arp, icmp};

/// Every ARP request in a batch goes out before any reply is collected, so the
/// window is however long the slowest host takes to answer, not the sum over
/// the batch. Devices that defer ARP — phones with the screen off, say — can
/// take far longer than the per-connection `timeout_ms`, so the batch gets its
/// own floor rather than inheriting it.
const MIN_ARP_WINDOW_MS: u64 = 1500;

#[derive(Debug, Clone)]
pub struct HostResult {
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    pub method: DiscoveryMethod,
}

#[derive(Debug, Clone)]
pub enum DiscoveryMethod {
    Arp,
    Icmp,
}

/// Sweep a list of IPs — uses ARP if a local interface matches, ICMP otherwise.
/// Results are sent over `tx` as they arrive.
pub async fn sweep(targets: Vec<Ipv4Addr>, timeout_ms: u64, tx: Sender<HostResult>) {
    let interfaces = datalink::interfaces();

    // Targets on a local subnet are batched per interface so each interface is
    // opened once, rather than once per address.
    let mut local: HashMap<String, (NetworkInterface, Vec<Ipv4Addr>)> = HashMap::new();
    let mut remote: Vec<Ipv4Addr> = Vec::new();

    for target in targets {
        match find_local_interface(&interfaces, target) {
            Some(iface) => local
                .entry(iface.name.clone())
                .or_insert_with(|| (iface.clone(), Vec::new()))
                .1
                .push(target),
            None => remote.push(target),
        }
    }

    let mut tasks = JoinSet::new();
    let arp_window = timeout_ms.max(MIN_ARP_WINDOW_MS);

    for (iface, group) in local.into_values() {
        let tx = tx.clone();
        tasks.spawn(async move {
            let _ = tokio::task::spawn_blocking(move || {
                arp::sweep(&iface, &group, arp_window, |ip, mac| {
                    let _ = tx.blocking_send(HostResult {
                        ip,
                        mac: Some(mac.to_string()),
                        method: DiscoveryMethod::Arp,
                    });
                });
            })
            .await;
        });
    }

    for target in remote {
        let tx = tx.clone();
        tasks.spawn(async move {
            let alive = tokio::task::spawn_blocking(move || icmp::ping(target, timeout_ms)).await;
            if let Ok(true) = alive {
                let _ = tx
                    .send(HostResult {
                        ip: target,
                        mac: None,
                        method: DiscoveryMethod::Icmp,
                    })
                    .await;
            }
        });
    }

    while tasks.join_next().await.is_some() {}
}

/// Returns the local interface whose subnet contains `target`, if any.
fn find_local_interface<'a>(
    interfaces: &'a [NetworkInterface],
    target: Ipv4Addr,
) -> Option<&'a NetworkInterface> {
    interfaces.iter().find(|iface| {
        iface.ips.iter().any(|net| {
            if let std::net::IpAddr::V4(v4) = net.ip() {
                net.contains(std::net::IpAddr::V4(target)) && v4 != target
            } else {
                false
            }
        })
    })
}
