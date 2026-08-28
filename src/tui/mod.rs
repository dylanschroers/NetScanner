pub mod app;
pub mod menu;
pub mod passive;
pub mod picker;
pub mod ui;

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use tokio::sync::mpsc;

use crate::config::ScanConfig;
use crate::scanner::{banner, host, port};
use crate::scanner::host::HostResult;
use crate::scanner::port::PortResult;

use app::{App, ScanState};

pub enum TuiEvent {
    HostFound(HostResult),
    PortFound(PortResult),
    DiscoveryDone,
    ScanDone,
}

pub enum ScanExit {
    Quit,
    BackToMenu,
}

pub async fn run(config: &ScanConfig, targets: Vec<Ipv4Addr>) -> std::io::Result<ScanExit> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let total_ports = config.ports.len();
    let total_hosts = targets.len();
    let mut app = App::new(config.target.clone(), total_hosts, total_ports);

    let (event_tx, mut event_rx) = mpsc::channel::<TuiEvent>(512);

    // Ports attempted, not ports found. Carried out of band because `event_tx`
    // only ever sees the open ones, and pushing an event per closed port would
    // mean a quarter of a million messages on a /24.
    let scanned = Arc::new(AtomicUsize::new(0));

    let ports = config.ports.clone();
    let timeout_ms = config.timeout_ms;
    let scan_progress = Arc::clone(&scanned);
    tokio::spawn(async move {
        // The sweep runs alongside the drain rather than before it: it holds the
        // only senders, and blocks once the channel fills, so draining after it
        // finishes would deadlock on any scan with more results than capacity.
        // Running them together is also what makes results appear live.
        let (host_tx, mut host_rx) = mpsc::channel::<HostResult>(256);
        let sweeping = tokio::spawn(host::sweep(targets, timeout_ms, host_tx));

        let mut live_hosts = Vec::new();
        while let Some(h) = host_rx.recv().await {
            let _ = event_tx.send(TuiEvent::HostFound(h.clone())).await;
            live_hosts.push(h);
        }
        let _ = sweeping.await;
        let _ = event_tx.send(TuiEvent::DiscoveryDone).await;

        for host in &live_hosts {
            let (port_tx, mut port_rx) = mpsc::channel::<PortResult>(256);
            let scanning = tokio::spawn(port::scan(
                host.ip,
                ports.clone(),
                timeout_ms,
                port_tx,
                Arc::clone(&scan_progress),
            ));

            while let Some(mut p) = port_rx.recv().await {
                p.banner = banner::grab(p.ip, p.port, timeout_ms).await;
                let _ = event_tx.send(TuiEvent::PortFound(p)).await;
            }
            let _ = scanning.await;
        }
        let _ = event_tx.send(TuiEvent::ScanDone).await;
    });

    let mut exit = ScanExit::Quit;

    loop {
        app.scanned_ports = scanned.load(Ordering::Relaxed);
        terminal.draw(|f| ui::draw(f, &mut app))?;

        while let Ok(ev) = event_rx.try_recv() {
            match ev {
                TuiEvent::HostFound(h) => { app.hosts.push(h); }
                TuiEvent::PortFound(p) => { app.ports.push(p); }
                TuiEvent::DiscoveryDone => {
                    app.state = ScanState::Scanning;
                    app.total_ports = app.hosts.len() * total_ports;
                }
                TuiEvent::ScanDone => { app.state = ScanState::Done; }
            }
        }

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                // Windows delivers releases as well as presses; see menu.rs.
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') => { exit = ScanExit::Quit;       break; }
                    KeyCode::Esc       => { exit = ScanExit::BackToMenu;  break; }
                    KeyCode::Down      => app.scroll_hosts_down(),
                    KeyCode::Up        => app.scroll_hosts_up(),
                    _                  => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(exit)
}
