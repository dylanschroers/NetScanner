use pnet::packet::tcp::TcpPacket;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq)]
pub enum TcpScanFlags {
    Syn,
    SynAck,
    Rst,
    Other,
}

#[derive(Debug, Clone)]
pub struct TcpObservation {
    pub source_ip: Ipv4Addr,
    pub dest_ip: Ipv4Addr,
    pub dest_port: u16,
    pub flags: TcpScanFlags,
}

pub fn parse(source_ip: Ipv4Addr, dest_ip: Ipv4Addr, payload: &[u8]) -> Option<TcpObservation> {
    let tcp = TcpPacket::new(payload)?;
    let raw = tcp.get_flags();

    let syn = raw & pnet::packet::tcp::TcpFlags::SYN != 0;
    let ack = raw & pnet::packet::tcp::TcpFlags::ACK != 0;
    let rst = raw & pnet::packet::tcp::TcpFlags::RST != 0;

    let flags = match (syn, ack, rst) {
        (true, false, _) => TcpScanFlags::Syn,
        (true, true,  _) => TcpScanFlags::SynAck,
        (_,    _,  true) => TcpScanFlags::Rst,
        _                => TcpScanFlags::Other,
    };

    Some(TcpObservation {
        source_ip,
        dest_ip,
        dest_port: tcp.get_destination(),
        flags,
    })
}
