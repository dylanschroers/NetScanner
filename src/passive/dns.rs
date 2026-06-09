use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct DnsObservation {
    pub source_ip: Ipv4Addr,
    pub query: String,
    pub is_response: bool,
}

/// Parse a raw DNS UDP payload into a hostname query/response.
/// DNS wire format: 12-byte header, then question section.
pub fn parse(source_ip: Ipv4Addr, payload: &[u8]) -> Option<DnsObservation> {
    if payload.len() < 12 {
        return None;
    }

    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = (flags >> 15) & 1 == 1;
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);

    if qdcount == 0 {
        return None;
    }

    let query = parse_qname(payload, 12)?;
    if query.is_empty() {
        return None;
    }

    Some(DnsObservation { source_ip, query, is_response })
}

/// Walk the DNS label encoding starting at `offset` and return the dotted hostname.
fn parse_qname(buf: &[u8], mut offset: usize) -> Option<String> {
    let mut parts = Vec::new();
    let mut jumps = 0;

    loop {
        if offset >= buf.len() {
            return None;
        }
        let len = buf[offset] as usize;

        if len == 0 {
            break;
        }

        // Pointer (compression) — top two bits set
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= buf.len() {
                return None;
            }
            let ptr = (((len & 0x3F) as usize) << 8) | buf[offset + 1] as usize;
            offset = ptr;
            jumps += 1;
            if jumps > 10 {
                return None;
            }
            continue;
        }

        offset += 1;
        if offset + len > buf.len() {
            return None;
        }
        let label = std::str::from_utf8(&buf[offset..offset + len]).ok()?;
        parts.push(label.to_string());
        offset += len;
    }

    Some(parts.join("."))
}
