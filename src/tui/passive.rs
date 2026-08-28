use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
    Terminal,
};

use crate::passive::{CaptureError, PassiveEvent, arp::ArpOp, tcp::TcpScanFlags};

#[derive(Debug, Clone)]
struct HostEntry {
    ip: Ipv4Addr,
    mac: String,
    hostname: Option<String>,
    vendor: Option<String>,
}

#[derive(Debug, Clone)]
struct EventEntry {
    kind: String,
    detail: String,
}

/// What the capture thread is doing, as far as this screen can tell.
enum Capture {
    Running,
    /// `None` if the thread vanished without reporting, which must not be
    /// allowed to look like a healthy capture that has seen no traffic.
    Stopped(Option<CaptureError>),
}

pub fn run(iface: &str) -> std::io::Result<super::ScanExit> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    // Sync channel — capture() is blocking so we use std::sync::mpsc
    let (tx, rx) = std::sync::mpsc::sync_channel::<PassiveEvent>(512);
    // Separate from the events so a failure cannot queue behind a full buffer.
    let (status_tx, status_rx) = std::sync::mpsc::channel::<CaptureError>();
    let iface_name = iface.to_string();
    std::thread::spawn(move || {
        // `tx` outlives the call, so the reason is queued before the event
        // channel disconnects and the screen can always pair the two.
        if let Err(e) = crate::passive::capture(&iface_name, &tx) {
            let _ = status_tx.send(e);
        }
    });

    let mut hosts: HashMap<Ipv4Addr, HostEntry> = HashMap::new();
    let mut event_log: Vec<EventEntry> = Vec::new();
    let mut exit = super::ScanExit::Quit;
    let mut capture = Capture::Running;
    const MAX_LOG: usize = 50;

    loop {
        // Drain all pending capture events
        loop {
            let ev = match rx.try_recv() {
                Ok(ev) => ev,
                Err(TryRecvError::Empty) => break,
                // Without this a dead capture is indistinguishable from a
                // quiet network: both show an empty table forever.
                Err(TryRecvError::Disconnected) => {
                    if matches!(capture, Capture::Running) {
                        capture = Capture::Stopped(status_rx.try_recv().ok());
                    }
                    break;
                }
            };

            match ev {
                PassiveEvent::Device(obs) => {
                    // ARP is the richer source but not the only one, and never
                    // arrives at all on a network that suppresses broadcasts.
                    hosts.entry(obs.ip).or_insert_with(|| HostEntry {
                        ip: obs.ip,
                        mac: obs.mac.clone(),
                        hostname: None,
                        vendor: None,
                    });
                }
                PassiveEvent::Arp(obs) => {
                    let is_real_ip = !obs.sender_ip.is_unspecified();
                    if is_real_ip {
                        hosts.entry(obs.sender_ip).or_insert_with(|| HostEntry {
                            ip: obs.sender_ip,
                            mac: obs.sender_mac.clone(),
                            hostname: None,
                            vendor: None,
                        });
                    }
                    let detail = match obs.operation {
                        ArpOp::Request => format!("{} asks: who is {}?", obs.sender_ip, obs.target_ip),
                        ArpOp::Reply   => format!("{} is at {}", obs.sender_ip, obs.sender_mac),
                    };
                    push_event(&mut event_log, "ARP", &detail, MAX_LOG);
                }
                PassiveEvent::Dns(obs) => {
                    let kind = if obs.is_response { "DNS reply" } else { "DNS query" };
                    let detail = format!("{} → {}", obs.source_ip, obs.query);
                    push_event(&mut event_log, kind, &detail, MAX_LOG);
                }
                PassiveEvent::Dhcp(obs) => {
                    // A client is named by MAC from the first packet, but by
                    // address only once it has one. Resolved to a key first:
                    // the search and the fallback cannot both borrow mutably.
                    let key = obs
                        .client_mac
                        .as_ref()
                        .and_then(|mac| hosts.values().find(|h| &h.mac == mac).map(|h| h.ip))
                        .or(obs.client_ip);

                    if let Some(entry) = key.and_then(|ip| hosts.get_mut(&ip)) {
                        if obs.hostname.is_some() { entry.hostname = obs.hostname.clone(); }
                        if obs.vendor_class.is_some() { entry.vendor = obs.vendor_class.clone(); }
                    }

                    // Mid-handshake the MAC is all it has given us.
                    let who = obs
                        .client_ip
                        .map(|ip| ip.to_string())
                        .or_else(|| obs.client_mac.clone())
                        .unwrap_or_else(|| String::from("?"));
                    let hostname = obs.hostname.as_deref().unwrap_or("?");
                    let vendor   = obs.vendor_class.as_deref().unwrap_or("?");
                    let detail   = format!("{} hostname={} vendor={}", who, hostname, vendor);
                    push_event(&mut event_log, "DHCP", &detail, MAX_LOG);
                }
                PassiveEvent::Tcp(obs) => {
                    if obs.flags == TcpScanFlags::Syn {
                        let detail = format!(
                            "{} → {}:{}",
                            obs.source_ip, obs.dest_ip, obs.dest_port
                        );
                        push_event(&mut event_log, "TCP SYN", &detail, MAX_LOG);
                    }
                }
            }
        }

        // Draw
        terminal.draw(|f| {
            let area = f.area();

            // Built before the layout because the lines decide the banner's
            // height, and only exists when something is wrong so a working
            // capture still gives the whole screen to the tables.
            let failure = match &capture {
                Capture::Running => None,
                Capture::Stopped(reason) => Some(banner_lines(reason.as_ref())),
            };

            let mut constraints = vec![Constraint::Length(3)];
            if let Some(lines) = &failure {
                // Borders, the lines, and a spare row for one wrap.
                constraints.push(Constraint::Length(lines.len() as u16 + 3));
            }
            constraints.extend([
                Constraint::Percentage(45),
                Constraint::Min(8),
                Constraint::Length(1),
            ]);
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints(constraints)
                .split(area);

            // Everything below the banner shifts down by one when it is shown.
            let body = if failure.is_some() { 2 } else { 1 };

            // Header
            let mut header_spans = vec![
                Span::styled("NetScanner  ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw("passive mode  │  interface: "),
                Span::styled(iface, Style::default().fg(Color::Yellow)),
                Span::raw("  │  "),
                Span::styled(
                    format!("{} hosts", hosts.len()),
                    Style::default().fg(Color::Green),
                ),
            ];
            if failure.is_some() {
                header_spans.push(Span::raw("  │  "));
                header_spans.push(Span::styled(
                    "not listening",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ));
            }
            let header = Paragraph::new(Line::from(header_spans))
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(header, chunks[0]);

            // Failure banner
            if let Some(lines) = failure {
                let banner = Paragraph::new(lines)
                    .wrap(Wrap { trim: true })
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(Color::Red))
                            .title(" Capture Stopped "),
                    );
                f.render_widget(banner, chunks[1]);
            }

            // Hosts table
            let mut host_list: Vec<&HostEntry> = hosts.values().collect();
            host_list.sort_by_key(|h| h.ip);
            let host_rows: Vec<Row> = host_list.iter().map(|h| {
                Row::new(vec![
                    Cell::from(h.ip.to_string()).style(Style::default().fg(Color::Cyan)),
                    Cell::from(h.mac.as_str()),
                    Cell::from(h.hostname.as_deref().unwrap_or("—")),
                    Cell::from(h.vendor.as_deref().unwrap_or("—")),
                ])
            }).collect();

            let host_table = Table::new(
                host_rows,
                [
                    Constraint::Length(18),
                    Constraint::Length(20),
                    Constraint::Length(22),
                    Constraint::Min(16),
                ],
            )
            .header(
                Row::new(vec!["IP Address", "MAC Address", "Hostname", "Vendor"])
                    .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::White)),
            )
            .block(Block::default().borders(Borders::ALL).title(" Discovered Hosts "));
            f.render_widget(host_table, chunks[body]);

            // Event log
            let log_rows: Vec<Row> = event_log.iter().rev().map(|e| {
                let color = match e.kind.as_str() {
                    "ARP"     => Color::Yellow,
                    "DNS query" | "DNS reply" => Color::Blue,
                    "DHCP"    => Color::Magenta,
                    "TCP SYN" => Color::Green,
                    _         => Color::White,
                };
                Row::new(vec![
                    Cell::from(e.kind.as_str()).style(Style::default().fg(color)),
                    Cell::from(e.detail.as_str()),
                ])
            }).collect();

            let log_table = Table::new(
                log_rows,
                [Constraint::Length(12), Constraint::Min(30)],
            )
            .header(
                Row::new(vec!["Type", "Detail"])
                    .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::White)),
            )
            .block(Block::default().borders(Borders::ALL).title(" Live Event Log "));
            f.render_widget(log_table, chunks[body + 1]);

            // Footer
            let footer = Paragraph::new(Line::from(vec![
                Span::styled(" Esc", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw(" main menu  "),
                Span::styled("q", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw(" quit"),
            ]));
            f.render_widget(footer, chunks[body + 2]);
        })?;

        // Keyboard
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                // Windows delivers releases as well as presses; see menu.rs.
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') => { exit = super::ScanExit::Quit;      break; }
                    KeyCode::Esc       => { exit = super::ScanExit::BackToMenu; break; }
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(exit)
}

/// The failure message, then whatever can be done about it.
fn banner_lines(reason: Option<&CaptureError>) -> Vec<Line<'static>> {
    let message = match reason {
        Some(err) => err.to_string(),
        None => String::from("The capture stopped without reporting a reason."),
    };

    let mut lines = vec![Line::from(Span::styled(
        message,
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
    ))];

    for hint in reason.map(CaptureError::hints).unwrap_or_default() {
        lines.push(Line::from(Span::styled(
            hint,
            Style::default().fg(Color::DarkGray),
        )));
    }

    lines
}

fn push_event(log: &mut Vec<EventEntry>, kind: &str, detail: &str, max: usize) {
    if log.len() >= max {
        log.remove(0);
    }
    log.push(EventEntry { kind: kind.to_string(), detail: detail.to_string() });
}
