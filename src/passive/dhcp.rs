use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct DhcpObservation {
    /// The best address this message carries for the client, which for most of
    /// a handshake is not `ciaddr`: a DISCOVER and a selecting REQUEST both
    /// leave that field zero while still naming the host in their options.
    /// `None` when the message carries no address anywhere.
    pub client_ip: Option<Ipv4Addr>,
    /// `chaddr`, formatted the way pnet renders a `MacAddr`, so it matches the
    /// MAC an ARP observation records for the same host.
    pub client_mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor_class: Option<String>,
}

/// Offsets into the 236-byte fixed BOOTP header, which the magic cookie and
/// then the options section follow.
const HLEN: usize = 2;
const CIADDR: usize = 12;
const YIADDR: usize = 16;
const CHADDR: usize = 28;
const COOKIE: usize = 236;
const OPTIONS: usize = 240;

const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// Parse a DHCP UDP payload (port 67/68).
pub fn parse(payload: &[u8]) -> Option<DhcpObservation> {
    if payload.len() < OPTIONS {
        return None;
    }

    if payload[COOKIE..OPTIONS] != MAGIC_COOKIE {
        return None;
    }

    // `hlen` is the hardware address length. Anything other than a 6-byte
    // ethernet address is not something the host table could match against.
    let client_mac = (payload[HLEN] == 6).then(|| format_mac(&payload[CHADDR..CHADDR + 6]));

    let mut hostname = None;
    let mut vendor_class = None;
    let mut requested_ip = None;

    let mut i = OPTIONS;
    while i < payload.len() {
        let opt = payload[i];
        if opt == 255 { break; }  // end option
        if opt == 0  { i += 1; continue; }  // pad option

        i += 1;
        if i >= payload.len() { break; }
        let len = payload[i] as usize;
        i += 1;

        if i + len > payload.len() { break; }
        let data = &payload[i..i + len];

        match opt {
            12 => hostname     = std::str::from_utf8(data).ok().map(|s| s.to_string()),
            60 => vendor_class = std::str::from_utf8(data).ok().map(|s| s.to_string()),
            50 if len == 4 => requested_ip = addr_from(data),
            _  => {}
        }

        i += len;
    }

    Some(DhcpObservation {
        // A client that is already bound reports itself in `ciaddr`. Otherwise
        // the address in play is the one the server is handing out in `yiaddr`,
        // or the one the client is asking for in option 50.
        client_ip: addr_from(&payload[CIADDR..CIADDR + 4])
            .or_else(|| addr_from(&payload[YIADDR..YIADDR + 4]))
            .or(requested_ip),
        client_mac,
        hostname,
        vendor_class,
    })
}

/// Four bytes as an address, treating 0.0.0.0 as "no address given" — which is
/// what an unset BOOTP address field holds.
fn addr_from(bytes: &[u8]) -> Option<Ipv4Addr> {
    let addr = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
    (!addr.is_unspecified()).then_some(addr)
}

fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a DHCP payload with the given addresses and options.
    fn message(ciaddr: [u8; 4], yiaddr: [u8; 4], options: &[u8]) -> Vec<u8> {
        let mut payload = vec![0u8; COOKIE];
        payload[1] = 1; // htype: ethernet
        payload[HLEN] = 6;
        payload[CIADDR..CIADDR + 4].copy_from_slice(&ciaddr);
        payload[YIADDR..YIADDR + 4].copy_from_slice(&yiaddr);
        payload[CHADDR..CHADDR + 6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33]);
        payload.extend_from_slice(&MAGIC_COOKIE);
        payload.extend_from_slice(options);
        payload.push(255);
        payload
    }

    fn hostname_option() -> Vec<u8> {
        let mut opt = vec![12, 6];
        opt.extend_from_slice(b"laptop");
        opt
    }

    /// The message that actually carries the hostname is the one whose `ciaddr`
    /// is still zero, so reading `ciaddr` alone identified every such client as
    /// 0.0.0.0 and the hostname could never be matched to a host.
    #[test]
    fn a_discover_is_identified_by_its_mac_not_its_empty_ciaddr() {
        let obs = parse(&message([0, 0, 0, 0], [0, 0, 0, 0], &hostname_option())).unwrap();

        assert_eq!(obs.client_ip, None);
        assert_eq!(obs.client_mac.as_deref(), Some("aa:bb:cc:11:22:33"));
        assert_eq!(obs.hostname.as_deref(), Some("laptop"));
    }

    /// An ACK names the client only in `yiaddr`.
    #[test]
    fn an_ack_reports_the_address_the_server_assigned() {
        let obs = parse(&message([0, 0, 0, 0], [192, 168, 1, 77], &hostname_option())).unwrap();

        assert_eq!(obs.client_ip, Some(Ipv4Addr::new(192, 168, 1, 77)));
    }

    /// A selecting REQUEST leaves both address fields zero and puts the address
    /// it wants in option 50.
    #[test]
    fn a_selecting_request_falls_back_to_the_requested_address() {
        let mut options = hostname_option();
        options.extend_from_slice(&[50, 4, 192, 168, 1, 90]);

        let obs = parse(&message([0, 0, 0, 0], [0, 0, 0, 0], &options)).unwrap();

        assert_eq!(obs.client_ip, Some(Ipv4Addr::new(192, 168, 1, 90)));
    }

    /// A renewing client is already bound, and `ciaddr` is then the truth.
    #[test]
    fn a_bound_client_reports_its_own_address_first() {
        let mut options = hostname_option();
        options.extend_from_slice(&[50, 4, 10, 0, 0, 1]);

        let obs = parse(&message([192, 168, 1, 5], [0, 0, 0, 0], &options)).unwrap();

        assert_eq!(obs.client_ip, Some(Ipv4Addr::new(192, 168, 1, 5)));
    }

    #[test]
    fn vendor_class_is_read_alongside_the_hostname() {
        let mut options = hostname_option();
        options.extend_from_slice(&[60, 4]);
        options.extend_from_slice(b"MSFT");

        let obs = parse(&message([0, 0, 0, 0], [192, 168, 1, 77], &options)).unwrap();

        assert_eq!(obs.hostname.as_deref(), Some("laptop"));
        assert_eq!(obs.vendor_class.as_deref(), Some("MSFT"));
    }

    /// The MAC has to be written exactly as pnet writes an ARP sender's, or
    /// matching a DHCP message to a known host silently never fires.
    #[test]
    fn the_mac_matches_how_pnet_renders_one() {
        let pnet_rendered = pnet::util::MacAddr::new(0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33).to_string();

        let obs = parse(&message([0, 0, 0, 0], [0, 0, 0, 0], &[])).unwrap();

        assert_eq!(obs.client_mac, Some(pnet_rendered));
    }

    #[test]
    fn a_payload_without_the_magic_cookie_is_not_dhcp() {
        let mut payload = message([0, 0, 0, 0], [0, 0, 0, 0], &[]);
        payload[COOKIE] = 0;

        assert!(parse(&payload).is_none());
    }

    #[test]
    fn a_truncated_payload_is_rejected_rather_than_indexed_into() {
        assert!(parse(&[0u8; 100]).is_none());
    }
}
