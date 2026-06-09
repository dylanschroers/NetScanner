use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
use pnet::transport::{tcp_packet_iter, transport_channel, TransportChannelType};
use pnet::transport::TransportProtocol::Ipv4;
use std::net::Ipv4Addr;
use std::time::Duration;

const TCP_HEADER_LEN: usize = 20;

/// Sends a TCP SYN to `target:port` and returns true if a SYN-ACK is received.
/// A RST response means the port is closed. No response means filtered.
pub fn syn_scan(source_ip: Ipv4Addr, target: Ipv4Addr, port: u16, timeout_ms: u64) -> PortState {
    let protocol = TransportChannelType::Layer4(Ipv4(IpNextHeaderProtocols::Tcp));

    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok(pair) => pair,
        Err(_) => return PortState::Filtered,
    };

    let mut buf = vec![0u8; TCP_HEADER_LEN];
    let mut tcp = MutableTcpPacket::new(&mut buf).unwrap();

    tcp.set_source(49152);
    tcp.set_destination(port);
    tcp.set_sequence(rand_seq());
    tcp.set_acknowledgement(0);
    tcp.set_data_offset(5);
    tcp.set_flags(TcpFlags::SYN);
    tcp.set_window(65535);

    let checksum = ipv4_checksum(&tcp.to_immutable(), &source_ip, &target);
    tcp.set_checksum(checksum);

    if tx.send_to(tcp, std::net::IpAddr::V4(target)).is_err() {
        return PortState::Filtered;
    }

    let mut iter = tcp_packet_iter(&mut rx);
    let deadline = Duration::from_millis(timeout_ms);

    match iter.next_with_timeout(deadline) {
        Ok(Some((packet, addr))) => {
            if addr != std::net::IpAddr::V4(target) {
                return PortState::Filtered;
            }
            let flags = packet.get_flags();
            if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
                PortState::Open
            } else if flags & TcpFlags::RST != 0 {
                PortState::Closed
            } else {
                PortState::Filtered
            }
        }
        _ => PortState::Filtered,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

fn rand_seq() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(12345)
}
