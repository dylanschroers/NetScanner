use pnet::ipnetwork::Ipv4Network;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct DeviceObservation {
    pub ip: Ipv4Addr,
    pub mac: String,
}

/// An address and the MAC that carried it, when the pair describes a device on
/// this link.
///
/// Internet traffic arrives with the router's MAC beside a remote address, so
/// pairing every address with the MAC next to it would file half the internet
/// under the gateway. Only addresses inside the interface's subnet qualify.
pub fn on_link(
    ip: Ipv4Addr,
    mac: MacAddr,
    network: Option<Ipv4Network>,
) -> Option<DeviceObservation> {
    let network = network?;

    if !network.contains(ip) || ip == network.network() || ip == network.broadcast() {
        return None;
    }

    // A group address names no single machine; an all-zero MAC names nothing.
    if mac.is_zero() || mac.is_broadcast() || mac.is_multicast() {
        return None;
    }

    Some(DeviceObservation {
        ip,
        mac: mac.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn lan() -> Option<Ipv4Network> {
        Some(Ipv4Network::from_str("192.168.32.0/24").unwrap())
    }

    fn mac() -> MacAddr {
        MacAddr::new(0x68, 0x07, 0x15, 0x92, 0x3a, 0x24)
    }

    #[test]
    fn an_address_on_this_subnet_is_a_device() {
        let obs = on_link(Ipv4Addr::new(192, 168, 32, 35), mac(), lan()).unwrap();

        assert_eq!(obs.ip, Ipv4Addr::new(192, 168, 32, 35));
        assert_eq!(obs.mac, "68:07:15:92:3a:24");
    }

    /// The point of the subnet check: recording the router's MAC against a
    /// remote address would invent a LAN device that does not exist.
    #[test]
    fn a_remote_address_is_not_a_device_on_this_link() {
        assert!(on_link(Ipv4Addr::new(160, 79, 104, 10), mac(), lan()).is_none());
    }

    #[test]
    fn the_subnets_own_network_and_broadcast_addresses_are_not_devices() {
        assert!(on_link(Ipv4Addr::new(192, 168, 32, 0), mac(), lan()).is_none());
        assert!(on_link(Ipv4Addr::new(192, 168, 32, 255), mac(), lan()).is_none());
    }

    #[test]
    fn a_group_address_is_not_a_machine() {
        let ip = Ipv4Addr::new(192, 168, 32, 40);
        assert!(on_link(ip, MacAddr::broadcast(), lan()).is_none());
        assert!(on_link(ip, MacAddr::new(0x01, 0x00, 0x5e, 0, 0, 0xfb), lan()).is_none());
        assert!(on_link(ip, MacAddr::zero(), lan()).is_none());
    }

    /// A mirror port cannot say what is on-link, so it claims nothing.
    #[test]
    fn an_interface_without_a_subnet_reports_nothing() {
        assert!(on_link(Ipv4Addr::new(192, 168, 32, 35), mac(), None).is_none());
    }
}
