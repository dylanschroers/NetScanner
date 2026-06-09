use std::net::Ipv4Addr;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinSet;
use pnet::datalink;

use crate::packet::{arp, icmp};

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
    let mut tasks = JoinSet::new();

    for target in targets {
        let tx = tx.clone();
        let iface = find_local_interface(&interfaces, target).cloned();

        tasks.spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                if let Some(iface) = iface {
                    // target is on a local subnet — use ARP
                    let mac = arp::arp_request(&iface, target, timeout_ms);
                    mac.map(|m| HostResult {
                        ip: target,
                        mac: Some(m.to_string()),
                        method: DiscoveryMethod::Arp,
                    })
                } else {
                    // target is remote — use ICMP ping
                    if icmp::ping(target, timeout_ms) {
                        Some(HostResult {
                            ip: target,
                            mac: None,
                            method: DiscoveryMethod::Icmp,
                        })
                    } else {
                        None
                    }
                }
            })
            .await;

            if let Ok(Some(host)) = result {
                let _ = tx.send(host).await;
            }
        });
    }

    while tasks.join_next().await.is_some() {}
}

/// Returns the local interface whose subnet contains `target`, if any.
fn find_local_interface<'a>(
    interfaces: &'a [datalink::NetworkInterface],
    target: Ipv4Addr,
) -> Option<&'a datalink::NetworkInterface> {
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
