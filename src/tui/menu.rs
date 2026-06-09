use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Terminal,
};

// What the menu returns to main once the user confirms their config
pub enum MenuResult {
    Active { target: String, ports: String, timeout: u64 },
    Passive { interface: String },
    Quit,
}

#[derive(PartialEq)]
enum Screen {
    SelectMode,
    ActiveInput,
    PassiveInput,
}

struct MenuState {
    screen: Screen,
    selected: usize,          // 0 = Active, 1 = Passive on the mode screen
    target: String,
    ports: String,
    interface: String,
    focused_field: usize,     // which input field is active
    error: Option<String>,
}

impl MenuState {
    fn new() -> Self {
        Self {
            screen: Screen::SelectMode,
            selected: 0,
            target: String::new(),
            ports: String::from("1-1024"),
            interface: String::from("en0"),
            focused_field: 0,
            error: None,
        }
    }
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
        terminal.draw(|f| draw(f, &state))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
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
                        KeyCode::Tab | KeyCode::Down => {
                            state.focused_field = (state.focused_field + 1) % 2;
                        }
                        KeyCode::BackTab | KeyCode::Up => {
                            state.focused_field = state.focused_field.saturating_sub(1);
                        }
                        KeyCode::Char(c) => {
                            state.error = None;
                            match state.focused_field {
                                0 => state.target.push(c),
                                1 => state.ports.push(c),
                                _ => {}
                            }
                        }
                        KeyCode::Backspace => match state.focused_field {
                            0 => { state.target.pop(); }
                            1 => { state.ports.pop(); }
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
                        KeyCode::Esc => {
                            state.screen = Screen::SelectMode;
                            state.error = None;
                        }
                        _ => {}
                    },

                    Screen::PassiveInput => match key.code {
                        KeyCode::Char(c) => {
                            state.error = None;
                            state.interface.push(c);
                        }
                        KeyCode::Backspace => { state.interface.pop(); }
                        KeyCode::Enter => {
                            if state.interface.trim().is_empty() {
                                state.error = Some("Interface is required".into());
                            } else {
                                result = MenuResult::Passive {
                                    interface: state.interface.trim().to_string(),
                                };
                                break;
                            }
                        }
                        KeyCode::Esc => {
                            state.screen = Screen::SelectMode;
                            state.error = None;
                        }
                        _ => {}
                    },
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(result)
}

fn draw(f: &mut ratatui::Frame, state: &MenuState) {
    let area = f.area();

    // Dark background
    let bg = Block::default().style(Style::default().bg(Color::Black));
    f.render_widget(bg, area);

    // Center a box in the screen
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(20),
            Constraint::Min(20),
            Constraint::Percentage(20),
        ])
        .split(area);

    let horiz = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Min(40),
            Constraint::Percentage(25),
        ])
        .split(vert[1]);

    let panel = horiz[1];
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
            Constraint::Length(4),  // title
            Constraint::Length(3),  // option 1
            Constraint::Length(3),  // option 2
            Constraint::Length(2),  // footer
        ])
        .split(area);

    let title = Paragraph::new(vec![
        Line::from(Span::styled(
            "NetScanner",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "Select scan mode",
            Style::default().fg(Color::DarkGray),
        )),
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

fn draw_active_input(f: &mut ratatui::Frame, state: &MenuState, area: ratatui::layout::Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // title
            Constraint::Length(3),  // target field
            Constraint::Length(3),  // ports field
            Constraint::Length(2),  // error / footer
        ])
        .split(area);

    let title = Paragraph::new("Active Scan")
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    let target_style = if state.focused_field == 0 {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let target = Paragraph::new(state.target.as_str())
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(" Target (IP or CIDR) ", target_style)),
        );
    f.render_widget(target, chunks[1]);

    let ports_style = if state.focused_field == 1 {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let ports = Paragraph::new(state.ports.as_str())
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(" Ports ", ports_style)),
        );
    f.render_widget(ports, chunks[2]);

    draw_input_footer(f, state, chunks[3]);
}

fn draw_passive_input(f: &mut ratatui::Frame, state: &MenuState, area: ratatui::layout::Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(2),
        ])
        .split(area);

    let title = Paragraph::new("Passive Capture")
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    let iface = Paragraph::new(state.interface.as_str())
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(" Interface ", Style::default().fg(Color::Cyan))),
        );
    f.render_widget(iface, chunks[1]);

    draw_input_footer(f, state, chunks[2]);
}

fn draw_input_footer(f: &mut ratatui::Frame, state: &MenuState, area: ratatui::layout::Rect) {
    let content = if let Some(err) = &state.error {
        Line::from(Span::styled(err.as_str(), Style::default().fg(Color::Red)))
    } else {
        Line::from(vec![
            Span::styled("Tab", Style::default().fg(Color::Yellow)),
            Span::raw(" next field  "),
            Span::styled("Enter", Style::default().fg(Color::Yellow)),
            Span::raw(" start  "),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::raw(" back"),
        ])
    };
    f.render_widget(Paragraph::new(content).alignment(Alignment::Center), area);
}
