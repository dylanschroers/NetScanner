use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone)]
pub struct PortResult {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub state: PortState,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

/// Scan all `ports` on `target` concurrently, sending open ports over `tx`.
/// Uses TCP connect scan — does not require root.
///
/// `scanned` counts every port that finished being probed, open or not. The
/// progress gauge needs attempts rather than hits, and `tx` only ever carries
/// the open ones.
pub async fn scan(
    target: Ipv4Addr,
    ports: Vec<u16>,
    timeout_ms: u64,
    tx: Sender<PortResult>,
    scanned: Arc<AtomicUsize>,
) {
    let mut tasks = JoinSet::new();
    let duration = Duration::from_millis(timeout_ms);

    for port in ports {
        let tx = tx.clone();
        let scanned = Arc::clone(&scanned);

        tasks.spawn(async move {
            let addr = format!("{}:{}", target, port);
            let state = match timeout(duration, TcpStream::connect(&addr)).await {
                Ok(Ok(_)) => PortState::Open,
                Ok(Err(_)) => PortState::Closed,
                Err(_) => PortState::Filtered,
            };

            if state == PortState::Open {
                let _ = tx.send(PortResult {
                    ip: target,
                    port,
                    state,
                    banner: None,
                }).await;
            }

            scanned.fetch_add(1, Ordering::Relaxed);
        });
    }

    while tasks.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The progress gauge divides this counter by every port it intends to
    /// probe, so counting only the open ones pinned the bar near zero.
    #[tokio::test]
    async fn counts_every_port_attempted_not_just_the_open_ones() {
        let ports: Vec<u16> = (1..=64).collect();
        let scanned = Arc::new(AtomicUsize::new(0));

        let (tx, mut rx) = tokio::sync::mpsc::channel::<PortResult>(8);
        let draining = tokio::spawn(async move {
            let mut open = 0;
            while rx.recv().await.is_some() {
                open += 1;
            }
            open
        });

        scan(
            Ipv4Addr::LOCALHOST,
            ports.clone(),
            100,
            tx,
            Arc::clone(&scanned),
        )
        .await;
        let open: usize = draining.await.unwrap();

        assert_eq!(scanned.load(Ordering::Relaxed), ports.len());
        assert!(open <= ports.len(), "reported more open ports than probed");
    }
}
