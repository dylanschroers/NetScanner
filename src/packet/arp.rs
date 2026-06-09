use pnet::datalink::{self, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::time::Duration;

const ETHERNET_HEADER_LEN: usize = 14;
const ARP_PACKET_LEN: usize = 28;

/// Sends an ARP request for `target` on `iface` and returns the MAC address if replied.
pub fn arp_request(iface: &NetworkInterface, target: Ipv4Addr, timeout_ms: u64) -> Option<MacAddr> {
    let source_mac = iface.mac?;
    let source_ip = iface.ips.iter().find_map(|ip| {
        if let std::net::IpAddr::V4(v4) = ip.ip() { Some(v4) } else { None }
    })?;

    let (mut tx, mut rx) = match datalink::channel(iface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => return None,
    };

    let mut eth_buf = vec![0u8; ETHERNET_HEADER_LEN + ARP_PACKET_LEN];
    build_arp_packet(&mut eth_buf, source_mac, source_ip, target);

    let _ = tx.send_to(&eth_buf, None);

    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if std::time::Instant::now() > deadline {
            return None;
        }
        if let Ok(frame) = rx.next() {
            if let Some(eth) = EthernetPacket::new(frame) {
                if eth.get_ethertype() == EtherTypes::Arp {
                    if let Some(arp) = ArpPacket::new(eth.payload()) {
                        if arp.get_operation() == ArpOperations::Reply
                            && arp.get_sender_proto_addr() == target
                        {
                            return Some(arp.get_sender_hw_addr());
                        }
                    }
                }
            }
        }
    }
}

fn build_arp_packet(buf: &mut [u8], src_mac: MacAddr, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) {
    let mut eth = MutableEthernetPacket::new(buf).unwrap();
    eth.set_destination(MacAddr::broadcast());
    eth.set_source(src_mac);
    eth.set_ethertype(EtherTypes::Arp);

    let mut arp = MutableArpPacket::new(eth.payload_mut()).unwrap();
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Request);
    arp.set_sender_hw_addr(src_mac);
    arp.set_sender_proto_addr(src_ip);
    arp.set_target_hw_addr(MacAddr::zero());
    arp.set_target_proto_addr(dst_ip);
}
