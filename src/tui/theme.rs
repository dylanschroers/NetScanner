use ratatui::style::{Color, Modifier, Style};

pub fn title(focused: bool) -> Style {
    Style::default().fg(if focused { Color::Cyan } else { Color::DarkGray })
}

pub fn selected_row(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::default().add_modifier(Modifier::DIM)
    }
}

pub fn selection_marker(focused: bool) -> &'static str {
    if focused { "▶ " } else { "  " }
}
