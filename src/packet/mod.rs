pub mod arp;
pub mod icmp;
pub mod tcp;

use pnet::transport::TransportReceiver;
use std::time::Duration;

/// Sets a receive timeout on a transport socket so that a following blocking
/// `next()` returns instead of blocking forever when no reply arrives.
///
/// pnet's own `next_with_timeout` is `#[cfg(unix)]` only and does not compile
/// on Windows, so we set `SO_RCVTIMEO` directly via socket2 and then use the
/// cross-platform `next()`.
pub(crate) fn set_recv_timeout(rx: &TransportReceiver, dur: Duration) {
    use socket2::Socket;
    let raw = rx.socket.fd;

    // Wrap the raw handle without taking ownership: we hand it back with
    // `into_raw_*` afterwards so socket2 never closes pnet's socket.
    #[cfg(windows)]
    {
        use std::os::windows::io::{FromRawSocket, IntoRawSocket, RawSocket};
        let sock = unsafe { Socket::from_raw_socket(raw as RawSocket) };
        let _ = sock.set_read_timeout(Some(dur));
        let _ = sock.into_raw_socket();
    }
    #[cfg(unix)]
    {
        use std::os::unix::io::{FromRawFd, IntoRawFd};
        let sock = unsafe { Socket::from_raw_fd(raw) };
        let _ = sock.set_read_timeout(Some(dur));
        let _ = sock.into_raw_fd();
    }
}
