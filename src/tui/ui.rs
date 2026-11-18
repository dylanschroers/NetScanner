use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, HighlightSpacing, Paragraph, Row, Table},
};

use super::app::{App, Pane, ScanState};
use super::theme;

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

    let hosts_focused = app.focus == Pane::Hosts;
    let host_table = Table::new(
        host_rows,
        [Constraint::Length(18), Constraint::Length(20), Constraint::Length(10)],
    )
    .header(
        Row::new(vec!["IP Address", "MAC Address", "Method"])
            .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::White)),
    )
    .highlight_style(theme::selected_row(hosts_focused))
    .highlight_symbol(theme::selection_marker(hosts_focused))
    // Reserve the marker column even before a row is selected, so tabbing
    // between the tables does not shift their columns sideways.
    .highlight_spacing(HighlightSpacing::Always)
    .block(Block::default().borders(Borders::ALL).title(Span::styled(
        format!(" Live Hosts ({}) ", app.hosts.len()),
        theme::title(hosts_focused),
    )));

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

    let ports_focused = app.focus == Pane::Ports;
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
    .highlight_style(theme::selected_row(ports_focused))
    .highlight_symbol(theme::selection_marker(ports_focused))
    .highlight_spacing(HighlightSpacing::Always)
    .block(Block::default().borders(Borders::ALL).title(Span::styled(
        format!(" Open Ports ({}) ", app.ports.len()),
        theme::title(ports_focused),
    )));

    frame.render_stateful_widget(port_table, chunks[2], &mut app.port_table_state);

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
    let key = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" Tab", key),
        Span::raw(match app.focus {
            Pane::Hosts => " scroll ports  ",
            Pane::Ports => " scroll hosts  ",
        }),
        Span::styled("↑↓", key),
        Span::raw(" scroll  "),
        Span::styled("PgUp/PgDn", key),
        Span::raw(" page  "),
        Span::styled("Esc", key),
        Span::raw(" main menu  "),
        Span::styled("q", key),
        Span::raw(" quit"),
    ]));
    frame.render_widget(footer, chunks[4]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::host::{DiscoveryMethod, HostResult};
    use crate::scanner::port::{PortResult, PortState};
    use ratatui::{backend::TestBackend, Terminal};
    use std::net::Ipv4Addr;

    fn app() -> App {
        let mut app = App::new("192.168.1.0/24".into(), 254, 1024);
        app.state = ScanState::Done;
        app.hosts = (1..=3)
            .map(|i| HostResult {
                ip: Ipv4Addr::new(192, 168, 1, i),
                mac: Some(format!("aa:bb:cc:dd:ee:{i:02}")),
                method: DiscoveryMethod::Arp,
            })
            .collect();
        app.ports = [22u16, 80, 443]
            .into_iter()
            .map(|port| PortResult {
                ip: Ipv4Addr::new(192, 168, 1, 1),
                port,
                state: PortState::Open,
                banner: None,
            })
            .collect();
        app
    }

    fn render(app: &mut App) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(90, 34)).unwrap();
        terminal.draw(|f| draw(f, app)).unwrap();

        let buffer = terminal.backend().buffer().clone();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer.cell((x, y)).unwrap().symbol())
                    .collect::<String>()
            })
            .collect()
    }

    fn row_containing<'a>(lines: &'a [String], needle: &str) -> &'a str {
        lines
            .iter()
            .find(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("no row containing {needle:?}"))
    }

    /// The ports table was rendered without any state, so it could not be
    /// scrolled and anything past the visible rows was unreachable.
    #[test]
    fn both_tables_can_hold_the_selection() {
        let mut app = app();

        app.focus = Pane::Ports;
        // The first press enters the list at the top, so three land on the third
        // row.
        app.scroll(1);
        app.scroll(1);
        app.scroll(1);

        let lines = render(&mut app);
        assert!(
            row_containing(&lines, "443").contains('▶'),
            "the selected port row is not marked"
        );
        assert!(
            !row_containing(&lines, "22").contains('▶'),
            "more than one port row is marked"
        );
    }

    /// With two scrollable tables it has to be obvious which one the arrow keys
    /// will move.
    #[test]
    fn only_the_focused_table_shows_the_marker() {
        let mut app = app();
        app.scroll(1); // hosts
        app.toggle_focus();
        app.scroll(1); // ports

        let lines = render(&mut app);
        assert!(row_containing(&lines, "22").contains('▶'));
        assert!(
            !row_containing(&lines, "aa:bb:cc:dd:ee:01").contains('▶'),
            "the unfocused hosts table still shows the marker"
        );

        app.toggle_focus();
        let lines = render(&mut app);
        assert!(row_containing(&lines, "aa:bb:cc:dd:ee:01").contains('▶'));
        assert!(!row_containing(&lines, "22").contains('▶'));
    }
}
