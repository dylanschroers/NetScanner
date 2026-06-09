use std::net::Ipv4Addr;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

/// Connects to `target:port` and reads the first bytes the service sends.
/// Returns None if the connection fails or nothing is sent within the timeout.
pub async fn grab(target: Ipv4Addr, port: u16, timeout_ms: u64) -> Option<String> {
    let addr = format!("{}:{}", target, port);
    let duration = Duration::from_millis(timeout_ms);

    let mut stream = timeout(duration, TcpStream::connect(&addr)).await.ok()?.ok()?;

    let mut buf = vec![0u8; 256];
    let n = timeout(duration, stream.read(&mut buf)).await.ok()?.ok()?;

    if n == 0 {
        return None;
    }

    let raw = &buf[..n];
    let banner = String::from_utf8_lossy(raw)
        .trim()
        .replace(['\r', '\n'], " ")
        .to_string();

    if banner.is_empty() { None } else { Some(banner) }
}
