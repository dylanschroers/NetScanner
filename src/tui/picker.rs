use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, Borders, Cell, Padding, Row, Table, TableState},
    Frame,
};

/// Columns a picker shows, not counting the hotkey number it adds itself.
pub const COLUMNS: usize = 3;

/// Rows past this many have no hotkey; the arrow keys still reach them.
const MAX_HOTKEYS: usize = 9;

/// One selectable row.
///
/// `columns` is what the user reads and `value` is what the caller acts on,
/// because the two are not always the same thing: an interface's pnet name is a
/// `\Device\NPF_{GUID}` path on Windows, which has to be passed to the capture
/// but must never be what someone is asked to read or type.
#[derive(Clone, Debug, PartialEq)]
pub struct PickerItem {
    pub columns: [String; COLUMNS],
    pub value: String,
}

/// How a picker should be drawn on a given frame.
///
/// Grouped rather than passed loose because a screen with several controls also
/// has to say which one holds focus, and that is one argument too many.
pub struct PickerView<'a> {
    pub title: &'a str,
    pub headers: [&'a str; COLUMNS],
    pub widths: [Constraint; COLUMNS],
    /// Drives the highlight, so a picker sharing a screen with text fields does
    /// not look active while the caret is somewhere else.
    pub focused: bool,
}

/// What a key did, so the screen owning the picker knows whether to act on it.
pub enum PickerAction {
    /// Not a key the picker handles; the screen may still want it.
    Ignored,
    /// The highlight moved and nothing else needs to happen.
    Moved,
    /// The user committed to the highlighted row.
    Chosen,
}

/// A keyboard-driven list of choices, rendered as a table.
///
/// Deliberately carries nothing interface-specific: the active scan's target
/// field wants the same control over candidate subnets, so headers, widths and
/// rows are all supplied by whoever is showing it.
pub struct Picker {
    items: Vec<PickerItem>,
    state: TableState,
}

impl Picker {
    pub fn new(items: Vec<PickerItem>) -> Self {
        let mut state = TableState::default();
        state.select(if items.is_empty() { None } else { Some(0) });
        Self { items, state }
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Row count, so a screen can size its panel to the content.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn selected(&self) -> Option<&PickerItem> {
        self.state.selected().and_then(|i| self.items.get(i))
    }

    /// Digits jump to a row but do not confirm it. Committing stays on Enter so
    /// that a mistyped key cannot start a capture on the wrong interface.
    pub fn handle_key(&mut self, code: KeyCode) -> PickerAction {
        if self.items.is_empty() {
            return PickerAction::Ignored;
        }

        match code {
            KeyCode::Down | KeyCode::Char('j') => self.step(1),
            KeyCode::Up | KeyCode::Char('k') => self.step(-1),
            KeyCode::Home => self.select(0),
            KeyCode::End => self.select(self.items.len() - 1),
            KeyCode::Char(c @ '1'..='9') => {
                let index = c as usize - '1' as usize;
                if index < self.items.len() {
                    self.select(index)
                } else {
                    PickerAction::Ignored
                }
            }
            KeyCode::Enter => PickerAction::Chosen,
            _ => PickerAction::Ignored,
        }
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect, view: PickerView) {
        // Split the borrow so the rows can read `items` while the table renders
        // through `state`.
        let Self { items, state } = self;

        let rows: Vec<Row> = items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let mut cells = vec![
                    Cell::from(hotkey_label(i)).style(Style::default().fg(Color::DarkGray))
                ];
                cells.extend(item.columns.iter().map(|text| Cell::from(text.as_str())));
                Row::new(cells)
            })
            .collect();

        let mut header_cells = vec![Cell::from("#")];
        header_cells.extend(view.headers.into_iter().map(Cell::from));

        let mut all_widths = vec![Constraint::Length(2)];
        all_widths.extend(view.widths);

        let (highlight, title_style) = if view.focused {
            (
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
                Style::default().fg(Color::Cyan),
            )
        } else {
            (
                Style::default().add_modifier(Modifier::DIM),
                Style::default().fg(Color::DarkGray),
            )
        };

        let table = Table::new(rows, all_widths)
            .header(
                Row::new(header_cells)
                    .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::White)),
            )
            .highlight_style(highlight)
            .highlight_symbol(if view.focused { "▶ " } else { "  " })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Span::styled(view.title, title_style))
                    // Keeps the last column off the border.
                    .padding(Padding::horizontal(1)),
            );

        frame.render_stateful_widget(table, area, state);
    }

    fn select(&mut self, index: usize) -> PickerAction {
        self.state.select(Some(index));
        PickerAction::Moved
    }

    /// Clamps rather than wrapping, matching the host table's scrolling.
    fn step(&mut self, delta: isize) -> PickerAction {
        let last = self.items.len() as isize - 1;
        let current = self.state.selected().unwrap_or(0) as isize;
        self.select((current + delta).clamp(0, last) as usize)
    }
}

fn hotkey_label(index: usize) -> String {
    if index < MAX_HOTKEYS {
        (index + 1).to_string()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn picker_of(count: usize) -> Picker {
        Picker::new(
            (0..count)
                .map(|i| PickerItem {
                    columns: [format!("row {i}"), String::new(), String::new()],
                    value: format!("value {i}"),
                })
                .collect(),
        )
    }

    fn selected_value(picker: &Picker) -> Option<&str> {
        picker.selected().map(|item| item.value.as_str())
    }

    #[test]
    fn starts_on_the_first_row() {
        assert_eq!(selected_value(&picker_of(3)), Some("value 0"));
    }

    #[test]
    fn digits_jump_straight_to_a_row() {
        let mut picker = picker_of(9);
        picker.handle_key(KeyCode::Char('7'));
        assert_eq!(selected_value(&picker), Some("value 6"));
    }

    /// A digit past the end must not move the highlight, or a stray keystroke
    /// would silently retarget the choice.
    #[test]
    fn digits_past_the_last_row_do_nothing() {
        let mut picker = picker_of(3);
        picker.handle_key(KeyCode::Char('8'));
        assert_eq!(selected_value(&picker), Some("value 0"));
    }

    #[test]
    fn digits_never_confirm_on_their_own() {
        let mut picker = picker_of(3);
        assert!(matches!(
            picker.handle_key(KeyCode::Char('2')),
            PickerAction::Moved
        ));
        assert!(matches!(
            picker.handle_key(KeyCode::Enter),
            PickerAction::Chosen
        ));
    }

    #[test]
    fn arrows_clamp_at_both_ends() {
        let mut picker = picker_of(2);
        picker.handle_key(KeyCode::Up);
        assert_eq!(selected_value(&picker), Some("value 0"));

        for _ in 0..5 {
            picker.handle_key(KeyCode::Down);
        }
        assert_eq!(selected_value(&picker), Some("value 1"));
    }

    /// Rows beyond the hotkey range are still reachable, just unnumbered.
    #[test]
    fn rows_past_the_hotkey_range_are_unnumbered_but_selectable() {
        assert_eq!(hotkey_label(8), "9");
        assert_eq!(hotkey_label(9), "");

        let mut picker = picker_of(12);
        picker.handle_key(KeyCode::End);
        assert_eq!(selected_value(&picker), Some("value 11"));
    }

    #[test]
    fn an_empty_picker_selects_nothing_and_consumes_nothing() {
        let mut picker = picker_of(0);
        assert!(picker.selected().is_none());
        assert!(matches!(
            picker.handle_key(KeyCode::Enter),
            PickerAction::Ignored
        ));
    }
}
