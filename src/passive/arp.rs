use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct ArpObservation {
    pub sender_ip: Ipv4Addr,
    pub sender_mac: String,
    pub target_ip: Ipv4Addr,
    pub operation: ArpOp,
}

#[derive(Debug, Clone)]
pub enum ArpOp {
    Request,
    Reply,
}

pub fn parse(frame: &EthernetPacket) -> Option<ArpObservation> {
    let arp = ArpPacket::new(frame.payload())?;

    let op = match arp.get_operation().0 {
        1 => ArpOp::Request,
        2 => ArpOp::Reply,
        _ => return None,
    };

    Some(ArpObservation {
        sender_ip: arp.get_sender_proto_addr(),
        sender_mac: arp.get_sender_hw_addr().to_string(),
        target_ip: arp.get_target_proto_addr(),
        operation: op,
    })
}
