use pnet::datalink::{self, NetworkInterface};
use pnet::ipnetwork::{IpNetwork, Ipv4Network};
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
///
/// Two things this has to get right, both of which bite on Windows:
///
/// Unconfigured adapters report `0.0.0.0/0`, and a /0 contains every address in
/// IPv4. Matching on containment alone hands every target to whichever such
/// adapter enumerates first — a Bluetooth PAN, say — so the sweep ARPs into the
/// void and even remote addresses never fall through to ICMP.
///
/// And where several interfaces genuinely match, the most specific subnet wins,
/// as it would in a routing table. Taking the first match instead would leave
/// the choice to enumeration order.
fn find_local_interface<'a>(
    interfaces: &'a [NetworkInterface],
    target: Ipv4Addr,
) -> Option<&'a NetworkInterface> {
    interfaces
        .iter()
        .filter_map(|iface| {
            let prefix = iface.ips.iter().filter_map(|net| match net {
                IpNetwork::V4(v4)
                    if is_real_subnet(v4) && v4.contains(target) && v4.ip() != target =>
                {
                    Some(v4.prefix())
                }
                _ => None,
            });
            prefix.max().map(|prefix| (prefix, iface))
        })
        .max_by_key(|(prefix, _)| *prefix)
        .map(|(_, iface)| iface)
}

/// Whether the network describes a subnet this host is really attached to,
/// rather than an unconfigured or self-assigned placeholder.
fn is_real_subnet(net: &Ipv4Network) -> bool {
    net.prefix() > 0
        && !net.ip().is_unspecified()
        && !net.ip().is_loopback()
        && !net.ip().is_link_local()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::util::MacAddr;

    fn iface(description: &str, cidrs: &[&str]) -> NetworkInterface {
        NetworkInterface {
            name: description.to_string(),
            description: description.to_string(),
            index: 0,
            mac: Some(MacAddr::new(2, 0, 0, 0, 0, 1)),
            ips: cidrs.iter().map(|c| c.parse().unwrap()).collect(),
            flags: 0,
        }
    }

    fn chosen<'a>(interfaces: &'a [NetworkInterface], target: &str) -> Option<&'a str> {
        find_local_interface(interfaces, target.parse().unwrap())
            .map(|iface| iface.description.as_str())
    }

    /// Windows reports unconfigured adapters as 0.0.0.0/0, and a /0 contains
    /// every address in IPv4. When one of those enumerated first it captured
    /// every target, so the sweep ARPed on a Bluetooth adapter and found
    /// nothing at all.
    #[test]
    fn unconfigured_adapters_do_not_capture_every_target() {
        let interfaces = [
            iface("Bluetooth", &["0.0.0.0/0"]),
            iface("Wi-Fi", &["0.0.0.0/0"]),
            iface("Ethernet", &["192.168.1.244/24"]),
        ];

        assert_eq!(chosen(&interfaces, "192.168.1.60"), Some("Ethernet"));
    }

    /// The same bug stopped remote addresses reaching the ICMP path, because a
    /// /0 claimed those too.
    #[test]
    fn a_remote_target_matches_no_interface() {
        let interfaces = [
            iface("Bluetooth", &["0.0.0.0/0"]),
            iface("Ethernet", &["192.168.1.244/24"]),
        ];

        assert_eq!(chosen(&interfaces, "8.8.8.8"), None);
    }

    /// Enumeration order must not decide which interface handles a target.
    #[test]
    fn the_most_specific_subnet_wins() {
        let interfaces = [
            iface("Wide", &["192.168.0.9/16"]),
            iface("Narrow", &["192.168.1.244/24"]),
        ];
        assert_eq!(chosen(&interfaces, "192.168.1.60"), Some("Narrow"));

        let reversed = [
            iface("Narrow", &["192.168.1.244/24"]),
            iface("Wide", &["192.168.0.9/16"]),
        ];
        assert_eq!(chosen(&reversed, "192.168.1.60"), Some("Narrow"));
    }

    /// Self-assigned link-local addresses are not a subnet worth ARPing.
    #[test]
    fn link_local_addresses_are_not_treated_as_a_subnet() {
        let interfaces = [iface("Idle", &["169.254.44.182/16"])];

        assert_eq!(chosen(&interfaces, "169.254.44.200"), None);
    }

    /// You cannot ARP for yourself.
    #[test]
    fn our_own_address_is_not_a_local_target() {
        let interfaces = [iface("Ethernet", &["192.168.1.244/24"])];

        assert_eq!(chosen(&interfaces, "192.168.1.244"), None);
        assert_eq!(chosen(&interfaces, "192.168.1.1"), Some("Ethernet"));
    }
}
