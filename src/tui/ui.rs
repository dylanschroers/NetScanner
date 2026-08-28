use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table},
};

use super::app::{App, ScanState};

pub fn draw(frame: &mut Frame, app: &mut App) {
    let area = frame.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Min(8),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(area);

    // --- Header ---
    let status = match app.state {
        ScanState::Discovering => "Discovering hosts...",
        ScanState::Scanning    => "Scanning ports...",
        ScanState::Done        => "Scan complete",
    };
    let header = Paragraph::new(Line::from(vec![
        Span::styled("NetScanner  ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("target: "),
        Span::styled(&app.target, Style::default().fg(Color::Yellow)),
        Span::raw("  │  "),
        Span::styled(status, Style::default().fg(Color::Green)),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    // --- Hosts table (stateful — supports scrolling) ---
    let host_rows: Vec<Row> = app.hosts.iter().map(|h| {
        Row::new(vec![
            Cell::from(h.ip.to_string()).style(Style::default().fg(Color::Cyan)),
            Cell::from(h.mac.as_deref().unwrap_or("—")),
            Cell::from(format!("{:?}", h.method)),
        ])
    }).collect();

    let host_table = Table::new(
        host_rows,
        [Constraint::Length(18), Constraint::Length(20), Constraint::Length(10)],
    )
    .header(
        Row::new(vec!["IP Address", "MAC Address", "Method"])
            .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::White)),
    )
    .highlight_style(
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ")
    .block(Block::default().borders(Borders::ALL).title(" Live Hosts  ↑↓ to scroll "));

    frame.render_stateful_widget(host_table, chunks[1], &mut app.host_table_state);

    // --- Ports table ---
    let port_rows: Vec<Row> = app.ports.iter().map(|p| {
        Row::new(vec![
            Cell::from(p.ip.to_string()).style(Style::default().fg(Color::Cyan)),
            Cell::from(p.port.to_string()).style(Style::default().fg(Color::Yellow)),
            Cell::from("open").style(Style::default().fg(Color::Green)),
            Cell::from(p.banner.as_deref().unwrap_or("—")),
        ])
    }).collect();

    let port_table = Table::new(
        port_rows,
        [
            Constraint::Length(18),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Min(20),
        ],
    )
    .header(
        Row::new(vec!["IP Address", "Port", "State", "Banner"])
            .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::White)),
    )
    .block(Block::default().borders(Borders::ALL).title(" Open Ports "));
    frame.render_widget(port_table, chunks[2]);

    // --- Progress bar ---
    // No port has been attempted yet during discovery, so a port count there
    // would just sit at zero for the whole sweep.
    let label = match app.state {
        ScanState::Discovering => format!(
            "probing {} address(es)  │  {} host(s) up",
            app.total_hosts, app.hosts.len()
        ),
        ScanState::Scanning => format!(
            "{}/{} ports scanned",
            app.scanned_ports, app.total_ports
        ),
        ScanState::Done => format!(
            "{} host(s) found  │  {} open port(s)",
            app.hosts.len(), app.ports.len()
        ),
    };
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(" Progress "))
        .gauge_style(Style::default().fg(Color::Cyan).bg(Color::Black))
        .ratio(app.progress().min(1.0))
        .label(label);
    frame.render_widget(gauge, chunks[3]);

    // --- Footer ---
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" ↑↓", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" scroll hosts  "),
        Span::styled("Esc", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" main menu  "),
        Span::styled("q", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" quit"),
    ]));
    frame.render_widget(footer, chunks[4]);
}
