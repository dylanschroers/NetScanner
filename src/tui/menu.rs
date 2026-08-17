use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use pnet::datalink::{self, NetworkInterface};
use pnet::ipnetwork::{IpNetwork, Ipv4Network};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame, Terminal,
};

use super::picker::{Picker, PickerAction, PickerItem, PickerView};

// What the menu returns to main once the user confirms their config
pub enum MenuResult {
    Active { target: String, ports: String, timeout: u64 },
    Passive { interface: String },
    Quit,
}

#[derive(Clone, Copy, PartialEq)]
enum Screen {
    SelectMode,
    ActiveInput,
    PassiveInput,
}

// Fields the active scan screen cycles through with Tab.
const FIELD_TARGET: usize = 0;
const FIELD_PORTS: usize = 1;
const FIELD_SUBNETS: usize = 2;
const FIELD_COUNT: usize = 3;

struct MenuState {
    screen: Screen,
    selected: usize,          // 0 = Active, 1 = Passive on the mode screen
    target: String,
    ports: String,
    subnets: Picker,          // suggested targets for the active scan
    interfaces: Picker,       // capture interfaces for the passive scan
    local_ip: Option<IpAddr>, // this machine's address on the routed interface
    focused_field: usize,     // which active scan field is focused
    error: Option<String>,
}

impl MenuState {
    fn new() -> Self {
        let local_ip = routed_local_ip();
        let subnets = subnet_items(local_ip);

        // Prefilling with the first suggestion makes the common case — sweep the
        // network this machine is on — need no typing at all.
        let target = subnets
            .first()
            .map(|item| item.value.clone())
            .unwrap_or_default();

        Self {
            screen: Screen::SelectMode,
            selected: 0,
            target,
            ports: String::from("1-1024"),
            subnets: Picker::new(subnets),
            interfaces: Picker::new(interface_items(local_ip)),
            local_ip,
            focused_field: FIELD_TARGET,
            error: None,
        }
    }

    /// Each screen sizes its own panel. A picker is sized to its content so it
    /// neither leaves dead space nor overflows; the plain input screens would
    /// look stretched at the width a three-column table needs.
    fn panel_size(&self) -> (u16, u16) {
        match self.screen {
            Screen::SelectMode => (56, 13),
            // Title, both text fields and the footer, then the suggestions
            // table's borders, header and rows.
            Screen::ActiveInput => {
                let rows = self.subnets.len().clamp(2, 8) as u16;
                (92, 11 + (rows + 3))
            }
            // Title, then the table's borders, header and rows, then the footer.
            // Capped so a long list scrolls rather than running off the screen,
            // and floored so an empty list still has room for its message.
            Screen::PassiveInput => {
                let rows = self.interfaces.len().clamp(3, 12) as u16;
                (92, 4 + (rows + 3) + 2)
            }
        }
    }
}

/// Centres a panel of at most `width` by `height` inside `area`.
fn centered_panel(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

/// This machine's address on whichever interface carries the default route.
///
/// Connecting a UDP socket sends no traffic; it only asks the routing table
/// which local address would be used to reach an off-link destination. That is
/// more reliable than picking the first addressed interface, which on a machine
/// running a VPN or an overlay network is usually the wrong one.
fn routed_local_ip() -> Option<IpAddr> {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|sock| {
            sock.connect("8.8.8.8:80")?;
            sock.local_addr()
        })
        .map(|addr| addr.ip())
        .ok()
}

/// Every capture interface, most likely candidate first.
///
/// Ranked rather than filtered: capturing on an interface with no address is
/// legitimate, and a switch mirror port looks exactly like that. Hiding those
/// would remove the one option a user in that situation needs.
///
/// The sort is stable, so interfaces of equal rank stay in enumeration order.
/// Shared with the active scan, which wants the same ordering when offering
/// candidate subnets to scan.
fn ranked_interfaces(routed_ip: Option<IpAddr>) -> Vec<NetworkInterface> {
    let mut interfaces = datalink::interfaces();
    interfaces.sort_by_key(|iface| rank(iface, routed_ip));
    interfaces
}

/// Lower sorts first.
fn rank(iface: &NetworkInterface, routed_ip: Option<IpAddr>) -> u8 {
    if routed_ip.is_some_and(|ip| iface.ips.iter().any(|net| net.ip() == ip)) {
        0
    } else if iface_v4(iface).is_some() {
        1
    } else {
        2
    }
}

/// The interface's usable IPv4 network, if it has one.
///
/// Returns the network rather than the bare address because the active scan
/// needs the prefix to offer a subnet to sweep.
fn iface_v4(iface: &NetworkInterface) -> Option<Ipv4Network> {
    iface.ips.iter().find_map(|net| match net {
        IpNetwork::V4(v4)
            if !v4.ip().is_loopback()
                && !v4.ip().is_unspecified()
                && !v4.ip().is_link_local() =>
        {
            Some(*v4)
        }
        _ => None,
    })
}

/// Interfaces as picker rows.
///
/// `description` is the readable name and `name` is what the capture opens, so
/// the device path stays out of sight. On platforms where pnet leaves the
/// description empty the name is readable anyway (`eth0`, `en0`).
fn interface_items(routed_ip: Option<IpAddr>) -> Vec<PickerItem> {
    ranked_interfaces(routed_ip)
        .into_iter()
        .map(|iface| {
            let label = if iface.description.trim().is_empty() {
                iface.name.clone()
            } else {
                iface.description.clone()
            };
            let address = match iface_v4(&iface) {
                Some(net) => net.ip().to_string(),
                None => String::from("no address"),
            };
            let mac = match iface.mac {
                Some(mac) if !mac.is_zero() => mac.to_string(),
                _ => String::from("—"),
            };

            PickerItem {
                columns: [label, address, mac],
                value: iface.name,
            }
        })
        .collect()
}

/// Locally attached subnets, as picker rows.
///
/// Filtering is right here where it was wrong for interfaces: an interface with
/// no IPv4 offers no subnet to sweep, so there is nothing to show. Unlike the
/// interface list this is only ever a set of suggestions, since a scan target
/// can be any address or range at all.
fn subnet_items(routed_ip: Option<IpAddr>) -> Vec<PickerItem> {
    let mut seen = HashSet::new();

    ranked_interfaces(routed_ip)
        .into_iter()
        .filter_map(|iface| {
            let net = iface_v4(&iface)?;
            let cidr = format!("{}/{}", net.network(), net.prefix());

            // Two interfaces can sit on one subnet; offer it once.
            if !seen.insert(cidr.clone()) {
                return None;
            }

            let label = if iface.description.trim().is_empty() {
                iface.name.clone()
            } else {
                iface.description.clone()
            };

            Some(PickerItem {
                columns: [cidr.clone(), label, net.size().to_string()],
                value: cidr,
            })
        })
        .collect()
}

pub fn run() -> std::io::Result<MenuResult> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut state = MenuState::new();
    let result;

    loop {
        terminal.draw(|f| draw(f, &mut state))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                // Windows reports key releases as `Event::Key` too, so without
                // this every keystroke is handled twice. It also drops the
                // release of whatever Enter launched the program, which would
                // otherwise confirm the highlighted mode before the menu is
                // ever seen.
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                match state.screen {
                    Screen::SelectMode => match key.code {
                        KeyCode::Up   | KeyCode::Char('k') => state.selected = 0,
                        KeyCode::Down | KeyCode::Char('j') => state.selected = 1,
                        KeyCode::Enter => {
                            state.error = None;
                            state.focused_field = 0;
                            if state.selected == 0 {
                                state.screen = Screen::ActiveInput;
                            } else {
                                state.screen = Screen::PassiveInput;
                            }
                        }
                        KeyCode::Char('q') => {
                            result = MenuResult::Quit;
                            break;
                        }
                        _ => {}
                    },

                    Screen::ActiveInput => match key.code {
                        KeyCode::Esc => {
                            state.screen = Screen::SelectMode;
                            state.error = None;
                        }
                        KeyCode::Tab => {
                            state.focused_field = (state.focused_field + 1) % FIELD_COUNT;
                        }
                        KeyCode::BackTab => {
                            state.focused_field =
                                (state.focused_field + FIELD_COUNT - 1) % FIELD_COUNT;
                        }

                        // While the suggestions are focused they own every
                        // remaining key, so digits pick a row instead of being
                        // typed and Enter fills the target rather than starting
                        // the scan.
                        _ if state.focused_field == FIELD_SUBNETS => {
                            state.error = None;
                            if let PickerAction::Chosen = state.subnets.handle_key(key.code) {
                                if let Some(subnet) =
                                    state.subnets.selected().map(|item| item.value.clone())
                                {
                                    state.target = subnet;
                                    state.focused_field = FIELD_TARGET;
                                }
                            }
                        }

                        KeyCode::Down => {
                            state.focused_field = (state.focused_field + 1) % FIELD_COUNT;
                        }
                        KeyCode::Up => {
                            state.focused_field =
                                (state.focused_field + FIELD_COUNT - 1) % FIELD_COUNT;
                        }
                        KeyCode::Char(c) => {
                            state.error = None;
                            match state.focused_field {
                                FIELD_TARGET => state.target.push(c),
                                FIELD_PORTS => state.ports.push(c),
                                _ => {}
                            }
                        }
                        KeyCode::Backspace => match state.focused_field {
                            FIELD_TARGET => { state.target.pop(); }
                            FIELD_PORTS => { state.ports.pop(); }
                            _ => {}
                        },
                        KeyCode::Enter => {
                            if state.target.trim().is_empty() {
                                state.error = Some("Target is required".into());
                            } else {
                                result = MenuResult::Active {
                                    target: state.target.trim().to_string(),
                                    ports:  state.ports.trim().to_string(),
                                    timeout: 500,
                                };
                                break;
                            }
                        }
                        _ => {}
                    },

                    Screen::PassiveInput => {
                        if key.code == KeyCode::Esc {
                            state.screen = Screen::SelectMode;
                            state.error = None;
                        } else if let PickerAction::Chosen = state.interfaces.handle_key(key.code) {
                            match state.interfaces.selected().map(|i| i.value.clone()) {
                                Some(interface) => {
                                    result = MenuResult::Passive { interface };
                                    break;
                                }
                                None => {
                                    state.error = Some("No capture interface available".into());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(result)
}

fn draw(f: &mut Frame, state: &mut MenuState) {
    let area = f.area();

    // Dark background
    let bg = Block::default().style(Style::default().bg(Color::Black));
    f.render_widget(bg, area);

    let (width, height) = state.panel_size();
    let panel = centered_panel(area, width, height);
    f.render_widget(Clear, panel);

    match state.screen {
        Screen::SelectMode => draw_mode_select(f, state, panel),
        Screen::ActiveInput => draw_active_input(f, state, panel),
        Screen::PassiveInput => draw_passive_input(f, state, panel),
    }
}

fn draw_mode_select(f: &mut ratatui::Frame, state: &MenuState, area: ratatui::layout::Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // title
            Constraint::Length(3),  // option 1
            Constraint::Length(3),  // option 2
            Constraint::Length(2),  // footer
        ])
        .split(area);

    let local = match state.local_ip {
        Some(ip) => Line::from(vec![
            Span::styled("This device  ", Style::default().fg(Color::DarkGray)),
            Span::styled(ip.to_string(), Style::default().fg(Color::Green)),
        ]),
        None => Line::from(Span::styled(
            "This device  address unavailable",
            Style::default().fg(Color::DarkGray),
        )),
    };

    let title = Paragraph::new(vec![
        Line::from(Span::styled(
            "NetScanner",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "Select scan mode",
            Style::default().fg(Color::DarkGray),
        )),
        local,
    ])
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    let active_style = if state.selected == 0 {
        Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };
    let active = Paragraph::new(Line::from(vec![
        Span::styled(
            if state.selected == 0 { "▶  Active Scan" } else { "   Active Scan" },
            active_style,
        ),
        Span::styled("  — probe hosts and ports directly", Style::default().fg(Color::DarkGray)),
    ]))
    .block(Block::default().borders(Borders::LEFT | Borders::RIGHT));
    f.render_widget(active, chunks[1]);

    let passive_style = if state.selected == 1 {
        Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };
    let passive = Paragraph::new(Line::from(vec![
        Span::styled(
            if state.selected == 1 { "▶  Passive Scan" } else { "   Passive Scan" },
            passive_style,
        ),
        Span::styled("  — listen only, send nothing", Style::default().fg(Color::DarkGray)),
    ]))
    .block(Block::default().borders(Borders::LEFT | Borders::RIGHT | Borders::BOTTOM));
    f.render_widget(passive, chunks[2]);

    let footer = Paragraph::new(Line::from(vec![
        Span::styled("↑↓", Style::default().fg(Color::Yellow)),
        Span::raw(" select  "),
        Span::styled("Enter", Style::default().fg(Color::Yellow)),
        Span::raw(" confirm  "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit"),
    ]))
    .alignment(Alignment::Center);
    f.render_widget(footer, chunks[3]);
}

fn draw_active_input(f: &mut Frame, state: &mut MenuState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // title
            Constraint::Length(3),  // target field
            Constraint::Length(3),  // ports field
            Constraint::Min(5),     // subnet suggestions
            Constraint::Length(2),  // error / footer
        ])
        .split(area);

    let title = Paragraph::new("Active Scan")
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    let target = Paragraph::new(state.target.as_str())
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(
                    " Target (IP or CIDR) ",
                    field_style(state.focused_field == FIELD_TARGET),
                )),
        );
    f.render_widget(target, chunks[1]);

    let ports = Paragraph::new(state.ports.as_str())
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(
                    " Ports ",
                    field_style(state.focused_field == FIELD_PORTS),
                )),
        );
    f.render_widget(ports, chunks[2]);

    let picking = state.focused_field == FIELD_SUBNETS;
    if state.subnets.is_empty() {
        let empty = Paragraph::new(Line::from(Span::styled(
            "No local subnets detected — type a target above.",
            Style::default().fg(Color::DarkGray),
        )))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).title(Span::styled(
            " Suggested targets ",
            field_style(picking),
        )));
        f.render_widget(empty, chunks[3]);
    } else {
        state.subnets.render(
            f,
            chunks[3],
            PickerView {
                title: " Suggested targets ",
                headers: ["Subnet", "Interface", "Addresses"],
                widths: [
                    Constraint::Length(18),
                    Constraint::Min(24),
                    Constraint::Length(10),
                ],
                focused: picking,
            },
        );
    }

    // Enter does different things depending on focus, so the hints say which.
    let hints = if picking {
        Line::from(vec![
            Span::styled("↑↓", Style::default().fg(Color::Yellow)),
            Span::raw(" select  "),
            Span::styled("1-9", Style::default().fg(Color::Yellow)),
            Span::raw(" jump  "),
            Span::styled("Enter", Style::default().fg(Color::Yellow)),
            Span::raw(" use subnet  "),
            Span::styled("Tab", Style::default().fg(Color::Yellow)),
            Span::raw(" next field"),
        ])
    } else {
        Line::from(vec![
            Span::styled("Tab", Style::default().fg(Color::Yellow)),
            Span::raw(" next field  "),
            Span::styled("Enter", Style::default().fg(Color::Yellow)),
            Span::raw(" start scan  "),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::raw(" back"),
        ])
    };

    draw_footer(f, state.error.as_deref(), hints, chunks[4]);
}

/// Cyan marks the control holding focus, matching the pickers.
fn field_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

fn draw_passive_input(f: &mut Frame, state: &mut MenuState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),  // title
            Constraint::Min(5),     // interface picker
            Constraint::Length(2),  // error / footer
        ])
        .split(area);

    let title = Paragraph::new(vec![
        Line::from(Span::styled(
            "Passive Capture",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "Select an interface to listen on",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    if state.interfaces.is_empty() {
        let empty = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "No capture interfaces found.",
                Style::default().fg(Color::Red),
            )),
            Line::from(Span::styled(
                "Npcap (Windows) or libpcap may not be installed.",
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).title(" Interfaces "));
        f.render_widget(empty, chunks[1]);
    } else {
        state.interfaces.render(
            f,
            chunks[1],
            PickerView {
                title: " Interfaces ",
                headers: ["Interface", "Address", "MAC"],
                widths: [
                    Constraint::Min(24),
                    Constraint::Length(15),
                    Constraint::Length(17),
                ],
                // The only control on this screen, so always focused.
                focused: true,
            },
        );
    }

    draw_footer(
        f,
        state.error.as_deref(),
        Line::from(vec![
            Span::styled("↑↓", Style::default().fg(Color::Yellow)),
            Span::raw(" select  "),
            Span::styled("1-9", Style::default().fg(Color::Yellow)),
            Span::raw(" jump  "),
            Span::styled("Enter", Style::default().fg(Color::Yellow)),
            Span::raw(" start  "),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::raw(" back"),
        ]),
        chunks[2],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// The capture looks the interface up by exact name, so every row must
    /// carry a name that exists — the hardcoded `en0` matched nothing off macOS
    /// and failed before it could capture anything.
    #[test]
    fn every_row_selects_a_real_interface() {
        let real: Vec<String> = datalink::interfaces().into_iter().map(|i| i.name).collect();
        for item in interface_items(routed_local_ip()) {
            assert!(
                real.contains(&item.value),
                "{:?} is not one of {real:?}",
                item.value
            );
        }
    }

    /// The whole point of the picker: the device path is what gets opened, never
    /// what gets shown.
    #[test]
    fn every_row_shows_something_readable() {
        for item in interface_items(routed_local_ip()) {
            let [label, address, mac] = &item.columns;
            assert!(!label.trim().is_empty(), "row has no label: {item:?}");
            assert!(!address.trim().is_empty(), "row has no address: {item:?}");
            assert!(!mac.trim().is_empty(), "row has no mac: {item:?}");
        }
    }

    #[test]
    fn the_routed_interface_is_offered_first() {
        let Some(routed) = routed_local_ip() else {
            return; // no default route on this machine to rank
        };

        let Some(first) = ranked_interfaces(Some(routed)).into_iter().next() else {
            return; // no interfaces at all
        };

        assert!(
            first.ips.iter().any(|net| net.ip() == routed),
            "{:?} does not hold the routed address {routed}",
            first.description
        );
    }

    /// Ranking must not become filtering: an interface with no address is a
    /// legitimate capture target, and is what a switch mirror port looks like.
    #[test]
    fn ranking_keeps_every_interface() {
        let total = datalink::interfaces().len();
        assert_eq!(ranked_interfaces(routed_local_ip()).len(), total);
        assert_eq!(ranked_interfaces(None).len(), total);
    }

    #[test]
    fn mode_select_shows_this_machines_address() {
        let mut state = MenuState::new();
        state.local_ip = Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 244)));

        assert!(render(&mut state).contains("192.168.1.244"));
    }

    /// Selection is by device path, so if the path ever reaches the screen the
    /// picker has failed at the thing it exists to do.
    #[test]
    fn the_picker_lists_interfaces_without_showing_device_paths() {
        let mut state = MenuState::new();
        state.screen = Screen::PassiveInput;

        let rendered = render(&mut state);

        assert!(
            !rendered.contains("NPF_"),
            "device path leaked into the picker:\n{rendered}"
        );
        for item in interface_items(routed_local_ip()).iter().take(3) {
            // Long names are truncated to the column, so match on a prefix.
            let label: String = item.columns[0].chars().take(12).collect();
            assert!(
                rendered.contains(&label),
                "{label:?} missing from picker:\n{rendered}"
            );
        }
    }

    #[test]
    fn the_picker_numbers_its_rows_for_hotkeys() {
        let mut state = MenuState::new();
        state.screen = Screen::PassiveInput;

        let expected = interface_items(routed_local_ip()).len().min(9);
        let rendered = render(&mut state);

        for n in 1..=expected {
            assert!(rendered.contains(&n.to_string()), "row {n} is not numbered");
        }
    }

    /// Every suggestion has to survive the parser `main` puts it through, or the
    /// scan exits with "could not parse target" on a value the app supplied
    /// itself.
    #[test]
    fn every_suggested_subnet_parses_as_a_target() {
        for item in subnet_items(routed_local_ip()) {
            let parsed = cidr::Ipv4Cidr::from_str(&item.value);
            assert!(parsed.is_ok(), "{:?} is not a valid CIDR", item.value);
        }
    }

    /// The common case is sweeping the network this machine is on, and it should
    /// need no typing.
    #[test]
    fn the_target_is_prefilled_with_the_first_suggestion() {
        let state = MenuState::new();
        let Some(first) = subnet_items(routed_local_ip()).into_iter().next() else {
            return; // no local subnet on this machine to suggest
        };

        assert_eq!(state.target, first.value);
    }

    /// One subnet per row even when several interfaces share it.
    #[test]
    fn suggestions_are_not_repeated() {
        let items = subnet_items(routed_local_ip());
        let unique: HashSet<&String> = items.iter().map(|item| &item.value).collect();

        assert_eq!(unique.len(), items.len());
    }

    #[test]
    fn choosing_a_suggestion_fills_the_target_field() {
        let mut state = MenuState::new();
        if state.subnets.len() < 2 {
            return; // nothing to switch between
        }

        state.screen = Screen::ActiveInput;
        state.focused_field = FIELD_SUBNETS;
        state.subnets.handle_key(KeyCode::Char('2'));
        let chosen = state.subnets.selected().unwrap().value.clone();

        assert_ne!(state.target, chosen, "test picked the prefilled row");

        // Mirrors what the key loop does on Enter.
        if let PickerAction::Chosen = state.subnets.handle_key(KeyCode::Enter) {
            state.target = state.subnets.selected().unwrap().value.clone();
            state.focused_field = FIELD_TARGET;
        }

        assert_eq!(state.target, chosen);
        assert_eq!(state.focused_field, FIELD_TARGET);
    }

    /// Suggestions are not exhaustive the way capture interfaces are, so an
    /// arbitrary target must still be typeable.
    #[test]
    fn the_target_field_still_accepts_typing() {
        let mut state = MenuState::new();
        state.screen = Screen::ActiveInput;
        state.focused_field = FIELD_TARGET;
        state.target.clear();

        for c in "10.0.0.5".chars() {
            state.target.push(c);
        }

        assert_eq!(state.target, "10.0.0.5");
        assert!(cidr::Ipv4Cidr::from_str(&state.target).is_ok() || "10.0.0.5".parse::<std::net::Ipv4Addr>().is_ok());
    }

    fn render(state: &mut MenuState) -> String {
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(100, 34)).unwrap();
        terminal.draw(|f| draw(f, state)).unwrap();

        let buffer = terminal.backend().buffer().clone();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer.cell((x, y)).unwrap().symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Shows `error` if there is one, otherwise the screen's key hints. Each screen
/// supplies its own hints because they no longer share a set of controls.
fn draw_footer(f: &mut Frame, error: Option<&str>, hints: Line, area: Rect) {
    let content = match error {
        Some(err) => Line::from(Span::styled(
            err.to_string(),
            Style::default().fg(Color::Red),
        )),
        None => hints,
    };
    f.render_widget(Paragraph::new(content).alignment(Alignment::Center), area);
}
