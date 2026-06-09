use std::net::Ipv4Addr;
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
pub async fn scan(target: Ipv4Addr, ports: Vec<u16>, timeout_ms: u64, tx: Sender<PortResult>) {
    let mut tasks = JoinSet::new();
    let duration = Duration::from_millis(timeout_ms);

    for port in ports {
        let tx = tx.clone();

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
        });
    }

    while tasks.join_next().await.is_some() {}
}
