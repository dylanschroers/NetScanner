use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{IcmpCode, IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{transport_channel, TransportChannelType, icmp_packet_iter};
use pnet::transport::TransportProtocol::Ipv4;
use std::net::Ipv4Addr;
use std::time::Duration;

const IPV4_HEADER_LEN: usize = 20;
const ICMP_HEADER_LEN: usize = 8;
const ICMP_PAYLOAD_LEN: usize = 32;
const TOTAL_LEN: usize = IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_PAYLOAD_LEN;

/// Sends an ICMP echo request to `target` and returns true if a reply is received
/// within `timeout_ms` milliseconds.
pub fn ping(target: Ipv4Addr, timeout_ms: u64) -> bool {
    let protocol = TransportChannelType::Layer4(Ipv4(IpNextHeaderProtocols::Icmp));

    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok(pair) => pair,
        Err(_) => return false,
    };

    let mut buf = vec![0u8; ICMP_HEADER_LEN + ICMP_PAYLOAD_LEN];
    let mut icmp = MutableEchoRequestPacket::new(&mut buf).unwrap();

    icmp.set_icmp_type(IcmpTypes::EchoRequest);
    icmp.set_icmp_code(IcmpCode::new(0));
    icmp.set_identifier(42);
    icmp.set_sequence_number(1);

    let checksum = pnet::packet::icmp::checksum(&IcmpPacket::new(icmp.packet()).unwrap());
    icmp.set_checksum(checksum);

    if tx.send_to(icmp, std::net::IpAddr::V4(target)).is_err() {
        return false;
    }

    super::set_recv_timeout(&rx, Duration::from_millis(timeout_ms));
    let mut iter = icmp_packet_iter(&mut rx);

    match iter.next() {
        Ok((packet, addr)) => {
            addr == std::net::IpAddr::V4(target)
                && packet.get_icmp_type() == IcmpTypes::EchoReply
        }
        Err(_) => false,
    }
}
