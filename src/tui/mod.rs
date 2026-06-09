pub mod app;
pub mod menu;
pub mod passive;
pub mod ui;

use std::net::Ipv4Addr;
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode},
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

    let ports = config.ports.clone();
    let timeout_ms = config.timeout_ms;
    tokio::spawn(async move {
        let (host_tx, mut host_rx) = mpsc::channel::<HostResult>(256);
        host::sweep(targets, timeout_ms, host_tx).await;

        let mut live_hosts = Vec::new();
        while let Ok(h) = host_rx.try_recv() {
            let _ = event_tx.send(TuiEvent::HostFound(h.clone())).await;
            live_hosts.push(h);
        }
        let _ = event_tx.send(TuiEvent::DiscoveryDone).await;

        for host in &live_hosts {
            let (port_tx, mut port_rx) = mpsc::channel::<PortResult>(256);
            port::scan(host.ip, ports.clone(), timeout_ms, port_tx).await;

            while let Ok(mut p) = port_rx.try_recv() {
                p.banner = banner::grab(p.ip, p.port, timeout_ms).await;
                let _ = event_tx.send(TuiEvent::PortFound(p)).await;
            }
        }
        let _ = event_tx.send(TuiEvent::ScanDone).await;
    });

    let mut exit = ScanExit::Quit;

    loop {
        terminal.draw(|f| ui::draw(f, &mut app))?;

        while let Ok(ev) = event_rx.try_recv() {
            match ev {
                TuiEvent::HostFound(h) => { app.hosts.push(h); }
                TuiEvent::PortFound(p) => {
                    app.scanned_ports += 1;
                    app.ports.push(p);
                }
                TuiEvent::DiscoveryDone => {
                    app.state = ScanState::Scanning;
                    app.total_ports = app.hosts.len() * total_ports;
                }
                TuiEvent::ScanDone => { app.state = ScanState::Done; }
            }
        }

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
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
