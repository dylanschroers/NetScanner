use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Terminal,
};

use crate::passive::{PassiveEvent, arp::ArpOp, tcp::TcpScanFlags};

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

pub fn run(iface: &str) -> std::io::Result<super::ScanExit> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    // Sync channel — capture() is blocking so we use std::sync::mpsc
    let (tx, rx) = std::sync::mpsc::sync_channel::<PassiveEvent>(512);
    let iface_name = iface.to_string();
    std::thread::spawn(move || {
        crate::passive::capture(&iface_name, tx);
    });

    let mut hosts: HashMap<Ipv4Addr, HostEntry> = HashMap::new();
    let mut event_log: Vec<EventEntry> = Vec::new();
    let mut exit = super::ScanExit::Quit;
    const MAX_LOG: usize = 50;

    loop {
        // Drain all pending capture events
        while let Ok(ev) = rx.try_recv() {
            match ev {
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
                    if let Some(entry) = hosts.get_mut(&obs.client_ip) {
                        if obs.hostname.is_some() { entry.hostname = obs.hostname.clone(); }
                        if obs.vendor_class.is_some() { entry.vendor = obs.vendor_class.clone(); }
                    }
                    let hostname = obs.hostname.as_deref().unwrap_or("?");
                    let vendor   = obs.vendor_class.as_deref().unwrap_or("?");
                    let detail   = format!("{} hostname={} vendor={}", obs.client_ip, hostname, vendor);
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
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Percentage(45),
                    Constraint::Min(8),
                    Constraint::Length(1),
                ])
                .split(area);

            // Header
            let header = Paragraph::new(Line::from(vec![
                Span::styled("NetScanner  ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw("passive mode  │  interface: "),
                Span::styled(iface, Style::default().fg(Color::Yellow)),
                Span::raw("  │  "),
                Span::styled(
                    format!("{} hosts", hosts.len()),
                    Style::default().fg(Color::Green),
                ),
            ]))
            .block(Block::default().borders(Borders::ALL));
            f.render_widget(header, chunks[0]);

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
            f.render_widget(host_table, chunks[1]);

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
            f.render_widget(log_table, chunks[2]);

            // Footer
            let footer = Paragraph::new(Line::from(vec![
                Span::styled(" Esc", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw(" main menu  "),
                Span::styled("q", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::raw(" quit"),
            ]));
            f.render_widget(footer, chunks[3]);
        })?;

        // Keyboard
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
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

fn push_event(log: &mut Vec<EventEntry>, kind: &str, detail: &str, max: usize) {
    if log.len() >= max {
        log.remove(0);
    }
    log.push(EventEntry { kind: kind.to_string(), detail: detail.to_string() });
}
