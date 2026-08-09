use pnet::datalink::{self, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

const ETHERNET_HEADER_LEN: usize = 14;
const ARP_PACKET_LEN: usize = 28;

/// Broadcasts an ARP request for every address in `targets` on `iface`, then
/// collects replies for up to `timeout_ms` total, invoking `on_reply` for each
/// distinct host that answers.
///
/// This opens a single channel for the whole batch rather than one per target:
/// a /24 sweep would otherwise open 254 Npcap adapters at once.
///
/// The receive loop runs on its own thread because the deadline cannot be
/// enforced inside it. `DataLinkReceiver::next` blocks with no way to interrupt
/// it, and `datalink::Config::read_timeout` is honoured only by the Linux, BPF
/// and netmap backends — on the winpcap backend Windows uses it is ignored
/// entirely, so a read on a silent link never returns.
pub fn sweep<F>(iface: &NetworkInterface, targets: &[Ipv4Addr], timeout_ms: u64, mut on_reply: F)
where
    F: FnMut(Ipv4Addr, MacAddr),
{
    let Some(source_mac) = iface.mac else { return };
    let Some(source_ip) = iface.ips.iter().find_map(|ip| match ip.ip() {
        std::net::IpAddr::V4(v4) => Some(v4),
        _ => None,
    }) else {
        return;
    };

    let (mut tx, rx) = match datalink::channel(iface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => return,
    };

    // Bounded so a flood of ARP traffic cannot grow the queue without limit;
    // the reader drops replies rather than blocking once it is full.
    let (reply_tx, reply_rx) = sync_channel::<(Ipv4Addr, MacAddr)>(256);
    let stop = Arc::new(AtomicBool::new(false));

    let reader_stop = Arc::clone(&stop);
    std::thread::spawn(move || read_replies(rx, reply_tx, reader_stop));

    let mut frame = vec![0u8; ETHERNET_HEADER_LEN + ARP_PACKET_LEN];
    for target in targets {
        build_arp_packet(&mut frame, source_mac, source_ip, *target);
        let _ = tx.send_to(&frame, None);
    }

    let wanted: HashSet<Ipv4Addr> = targets.iter().copied().collect();
    let mut seen = HashSet::new();
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);

    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match reply_rx.recv_timeout(remaining) {
            Ok((ip, mac)) => {
                // Other hosts' ARP chatter lands here too, so filter to the
                // batch and report each address only once.
                if wanted.contains(&ip) && seen.insert(ip) {
                    on_reply(ip, mac);
                }
            }
            Err(RecvTimeoutError::Timeout) => break,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    // The reader is parked in `next()`. Flag it, then put one more frame on the
    // wire so it wakes, observes the flag and drops the channel. On a silent
    // link this is the only thing that ends the thread; if the frame is lost the
    // thread exits on the next frame the interface sees instead.
    stop.store(true, Ordering::Relaxed);
    build_arp_packet(&mut frame, source_mac, source_ip, source_ip);
    let _ = tx.send_to(&frame, None);
}

fn read_replies(
    mut rx: Box<dyn datalink::DataLinkReceiver>,
    reply_tx: std::sync::mpsc::SyncSender<(Ipv4Addr, MacAddr)>,
    stop: Arc<AtomicBool>,
) {
    while let Ok(frame) = rx.next() {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let Some(eth) = EthernetPacket::new(frame) else { continue };
        if eth.get_ethertype() != EtherTypes::Arp {
            continue;
        }
        let Some(arp) = ArpPacket::new(eth.payload()) else { continue };
        if arp.get_operation() != ArpOperations::Reply {
            continue;
        }
        // A full queue means the consumer is behind or gone; either way there is
        // nothing useful to do but drop the reply.
        if reply_tx
            .try_send((arp.get_sender_proto_addr(), arp.get_sender_hw_addr()))
            .is_err()
        {
            continue;
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
