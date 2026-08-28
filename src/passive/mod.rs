pub mod arp;
pub mod device;
pub mod dhcp;
pub mod dns;
pub mod tcp;

use std::collections::HashSet;
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::mpsc::SyncSender;

use pnet::datalink::{self, Channel};
use pnet::ipnetwork::{IpNetwork, Ipv4Network};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;

use arp::ArpObservation;
use device::DeviceObservation;
use dns::DnsObservation;
use dhcp::DhcpObservation;
use tcp::TcpObservation;

#[derive(Debug, Clone)]
pub enum PassiveEvent {
    /// A machine on this link, worth listing whether or not the traffic that
    /// revealed it is a protocol we decode.
    Device(DeviceObservation),
    Arp(ArpObservation),
    Dns(DnsObservation),
    Dhcp(DhcpObservation),
    Tcp(TcpObservation),
}

/// Why a capture never started, or stopped.
///
/// Returned rather than printed: the TUI owns the alternate screen by the time
/// `capture` runs, so stderr is discarded when the terminal is restored and the
/// screen sits at zero hosts with no sign that nothing is listening.
#[derive(Debug, Clone)]
pub enum CaptureError {
    InterfaceNotFound { iface: String },
    /// Nearly always privileges.
    Open { iface: String, cause: String },
    Read { iface: String, cause: String },
}

/// Whether this process could open a capture channel at all, so the picker can
/// say so before an interface is chosen rather than one screen too late.
#[cfg(target_os = "linux")]
pub fn can_capture() -> bool {
    // Bit 13 of the capability bitmask. Root holds every bit, so this covers
    // sudo as well as a binary granted the one capability it needs.
    const CAP_NET_RAW: u32 = 13;

    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("CapEff:"))
                .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
        })
        .is_some_and(|caps| caps & (1 << CAP_NET_RAW) != 0)
}

/// Elsewhere there is no equally cheap answer; let the capture report failure.
#[cfg(not(target_os = "linux"))]
pub fn can_capture() -> bool {
    true
}

/// How to get capture rights, as lines to show the user. The Linux form names
/// this binary so the command can be pasted rather than transcribed.
#[cfg(target_os = "linux")]
pub fn privilege_hints() -> Vec<String> {
    let binary = std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| String::from("<binary>"));

    vec![
        String::from("Capture needs raw-socket access. Grant it once, then run again:"),
        // Unindented so it can be selected and copied as a whole line.
        format!("sudo setcap cap_net_raw+ep {binary}"),
        String::from("The grant is on the file, so re-run it after every rebuild."),
    ]
}

#[cfg(all(unix, not(target_os = "linux")))]
pub fn privilege_hints() -> Vec<String> {
    vec![String::from(
        "Capture needs raw-socket access: build first, then run the binary under sudo.",
    )]
}

#[cfg(windows)]
pub fn privilege_hints() -> Vec<String> {
    vec![String::from(
        "Capture needs Npcap installed, and NetScanner started as Administrator.",
    )]
}

impl CaptureError {
    /// What to do about it, shown beneath the message.
    pub fn hints(&self) -> Vec<String> {
        match self {
            Self::Open { .. } => privilege_hints(),
            Self::InterfaceNotFound { .. } => {
                vec![String::from("Go back and choose another interface.")]
            }
            Self::Read { .. } => Vec::new(),
        }
    }
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InterfaceNotFound { iface } => {
                write!(f, "Interface '{iface}' not found.")
            }
            Self::Open { iface, cause } => {
                write!(f, "Could not open '{iface}' for capture: {cause}.")
            }
            Self::Read { iface, cause } => {
                write!(f, "Capture on '{iface}' ended: {cause}.")
            }
        }
    }
}

/// Open `iface_name` in promiscuous mode and stream observed events over `tx`,
/// returning only once the capture has ended. Blocks indefinitely on a quiet
/// link, so it wants a thread of its own.
///
/// `tx` is borrowed, not consumed, so the caller still holds it on return and
/// can queue the error before the event channel disconnects.
pub fn capture(iface_name: &str, tx: &SyncSender<PassiveEvent>) -> Result<(), CaptureError> {
    let iface = datalink::interfaces()
        .into_iter()
        .find(|i| i.name == iface_name)
        .ok_or_else(|| CaptureError::InterfaceNotFound {
            iface: iface_name.to_string(),
        })?;

    // Separates a device on this link from a server on the internet whose
    // packets merely crossed the router. An addressless interface — a mirror
    // port — yields `None` and reports no devices, since it cannot know.
    let network = iface.ips.iter().find_map(|net| match net {
        IpNetwork::V4(v4)
            if !v4.ip().is_loopback()
                && !v4.ip().is_unspecified()
                && !v4.ip().is_link_local() =>
        {
            Some(*v4)
        }
        _ => None,
    });

    let config = datalink::Config {
        promiscuous: true,
        ..Default::default()
    };

    let mut rx = match datalink::channel(&iface, config) {
        Ok(Channel::Ethernet(_, rx)) => rx,
        Ok(_) => {
            return Err(CaptureError::Open {
                iface: iface_name.to_string(),
                cause: "not an ethernet link".to_string(),
            });
        }
        Err(e) => {
            return Err(CaptureError::Open {
                iface: iface_name.to_string(),
                cause: e.to_string(),
            });
        }
    };

    // Every packet after the first repeats who is on the network. Without this
    // a busy link would fill the channel with restatements and stall.
    let mut seen: HashSet<(Ipv4Addr, MacAddr)> = HashSet::new();

    loop {
        match rx.next() {
            Ok(frame) => {
                if let Some(eth) = EthernetPacket::new(frame) {
                    handle_ethernet(&eth, network, &mut seen, tx);
                }
            }
            Err(e) => {
                return Err(CaptureError::Read {
                    iface: iface_name.to_string(),
                    cause: e.to_string(),
                });
            }
        }
    }
}

fn handle_ethernet(
    eth: &EthernetPacket,
    network: Option<Ipv4Network>,
    seen: &mut HashSet<(Ipv4Addr, MacAddr)>,
    tx: &SyncSender<PassiveEvent>,
) {
    match eth.get_ethertype() {
        EtherTypes::Arp => {
            if let Some(obs) = arp::parse(eth) {
                let _ = tx.send(PassiveEvent::Arp(obs));
            }
        }
        EtherTypes::Ipv4 => {
            if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                report_devices(eth, &ip, network, seen, tx);
                handle_ipv4(&ip, tx);
            }
        }
        _ => {}
    }
}

/// Announce each end of the frame that is a device on this link, once each.
fn report_devices(
    eth: &EthernetPacket,
    ip: &Ipv4Packet,
    network: Option<Ipv4Network>,
    seen: &mut HashSet<(Ipv4Addr, MacAddr)>,
    tx: &SyncSender<PassiveEvent>,
) {
    let endpoints = [
        (ip.get_source(), eth.get_source()),
        (ip.get_destination(), eth.get_destination()),
    ];

    for (addr, mac) in endpoints {
        let Some(obs) = device::on_link(addr, mac, network) else {
            continue;
        };
        if seen.insert((addr, mac)) {
            let _ = tx.send(PassiveEvent::Device(obs));
        }
    }
}

fn handle_ipv4(ip: &Ipv4Packet, tx: &SyncSender<PassiveEvent>) {
    let src = ip.get_source();
    let dst = ip.get_destination();

    match ip.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            if let Some(obs) = tcp::parse(src, dst, ip.payload()) {
                let _ = tx.send(PassiveEvent::Tcp(obs));
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some(udp) = UdpPacket::new(ip.payload()) {
                let src_port = udp.get_source();
                let dst_port = udp.get_destination();

                // mDNS is the same wire format, and being multicast is the
                // name traffic likeliest to survive a network that isolates
                // its clients.
                if matches!(src_port, 53 | 5353) || matches!(dst_port, 53 | 5353) {
                    if let Some(obs) = dns::parse(src, udp.payload()) {
                        let _ = tx.send(PassiveEvent::Dns(obs));
                    }
                }

                // DHCP: client → server (68 → 67)
                if dst_port == 67 || dst_port == 68 {
                    if let Some(obs) = dhcp::parse(udp.payload()) {
                        let _ = tx.send(PassiveEvent::Dhcp(obs));
                    }
                }
            }
        }
        _ => {}
    }
}
