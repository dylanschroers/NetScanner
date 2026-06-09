use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct DhcpObservation {
    pub client_ip: Ipv4Addr,
    pub hostname: Option<String>,
    pub vendor_class: Option<String>,
}

/// Parse a DHCP UDP payload (port 67/68).
/// DHCP fixed header is 236 bytes, followed by 4-byte magic cookie, then options.
pub fn parse(payload: &[u8]) -> Option<DhcpObservation> {
    if payload.len() < 240 {
        return None;
    }

    // Magic cookie must be 99.130.83.99
    if &payload[236..240] != &[99, 130, 83, 99] {
        return None;
    }

    // Client IP address is at offset 12
    let client_ip = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);

    let mut hostname = None;
    let mut vendor_class = None;

    let mut i = 240;
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
            _  => {}
        }

        i += len;
    }

    Some(DhcpObservation { client_ip, hostname, vendor_class })
}
