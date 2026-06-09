pub mod arp;
pub mod dhcp;
pub mod dns;
pub mod tcp;

use pnet::datalink::{self, Channel};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use tokio::sync::mpsc::Sender;

use arp::ArpObservation;
use dns::DnsObservation;
use dhcp::DhcpObservation;
use tcp::TcpObservation;

#[derive(Debug, Clone)]
pub enum PassiveEvent {
    Arp(ArpObservation),
    Dns(DnsObservation),
    Dhcp(DhcpObservation),
    Tcp(TcpObservation),
}

/// Open `iface` in promiscuous mode and stream all observed events over `tx`.
/// This is blocking — must be called inside `tokio::task::spawn_blocking`.
pub fn capture(iface_name: &str, tx: std::sync::mpsc::SyncSender<PassiveEvent>) {
    let interfaces = datalink::interfaces();
    let iface = match interfaces.into_iter().find(|i| i.name == iface_name) {
        Some(i) => i,
        None => {
            eprintln!("Interface '{}' not found", iface_name);
            return;
        }
    };

    let config = datalink::Config {
        promiscuous: true,
        ..Default::default()
    };

    let (_, mut rx) = match datalink::channel(&iface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => {
            eprintln!("Failed to open datalink channel on '{}'", iface_name);
            return;
        }
    };

    loop {
        match rx.next() {
            Ok(frame) => {
                if let Some(eth) = EthernetPacket::new(frame) {
                    handle_ethernet(&eth, &tx);
                }
            }
            Err(e) => {
                eprintln!("Capture error: {e}");
                break;
            }
        }
    }
}

fn handle_ethernet(eth: &EthernetPacket, tx: &std::sync::mpsc::SyncSender<PassiveEvent>) {
    match eth.get_ethertype() {
        EtherTypes::Arp => {
            if let Some(obs) = arp::parse(eth) {
                let _ = tx.send(PassiveEvent::Arp(obs));
            }
        }
        EtherTypes::Ipv4 => {
            if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                handle_ipv4(&ip, tx);
            }
        }
        _ => {}
    }
}

fn handle_ipv4(ip: &Ipv4Packet, tx: &std::sync::mpsc::SyncSender<PassiveEvent>) {
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

                // DNS: port 53
                if src_port == 53 || dst_port == 53 {
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
