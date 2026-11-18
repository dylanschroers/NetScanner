use ratatui::widgets::TableState;
use crate::scanner::{host::HostResult, port::PortResult};

pub enum ScanState {
    Discovering,
    Scanning,
    Done,
}

/// Which results table the arrow keys move.
#[derive(Clone, Copy, PartialEq)]
pub enum Pane {
    Hosts,
    Ports,
}

pub struct App {
    pub target: String,
    pub total_hosts: usize,
    pub total_ports: usize,
    pub hosts: Vec<HostResult>,
    pub ports: Vec<PortResult>,
    pub scanned_ports: usize,
    pub state: ScanState,
    pub should_quit: bool,
    pub focus: Pane,
    pub host_table_state: TableState,
    pub port_table_state: TableState,
}

impl App {
    pub fn new(target: String, total_hosts: usize, total_ports: usize) -> Self {
        Self {
            target,
            total_hosts,
            total_ports,
            hosts: Vec::new(),
            ports: Vec::new(),
            scanned_ports: 0,
            state: ScanState::Discovering,
            should_quit: false,
            focus: Pane::Hosts,
            host_table_state: TableState::default(),
            port_table_state: TableState::default(),
        }
    }

    pub fn progress(&self) -> f64 {
        if self.total_ports == 0 {
            return 1.0;
        }
        self.scanned_ports as f64 / self.total_ports as f64
    }

    pub fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            Pane::Hosts => Pane::Ports,
            Pane::Ports => Pane::Hosts,
        };
    }

    /// Moves the selection in the focused table by `delta` rows.
    pub fn scroll(&mut self, delta: isize) {
        match self.focus {
            Pane::Hosts => scroll_table(&mut self.host_table_state, self.hosts.len(), delta),
            Pane::Ports => scroll_table(&mut self.port_table_state, self.ports.len(), delta),
        }
    }
}

/// Clamps at both ends rather than wrapping, matching the menu pickers.
///
/// The selection is an index, so a table that grows while the user is reading it
/// keeps whatever row they were on: results streaming in never yank the view.
fn scroll_table(state: &mut TableState, len: usize, delta: isize) {
    if len == 0 {
        state.select(None);
        return;
    }

    let last = len as isize - 1;
    let next = match state.selected() {
        Some(current) => (current as isize + delta).clamp(0, last),
        // Entering the list for the first time, come in from whichever end the
        // key was pointing at.
        None if delta < 0 => last,
        None => 0,
    };

    state.select(Some(next as usize));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_with(hosts: usize, ports: usize) -> App {
        let mut app = App::new("test".into(), hosts, ports);
        app.hosts = (0..hosts)
            .map(|i| HostResult {
                ip: std::net::Ipv4Addr::new(192, 168, 1, i as u8),
                mac: None,
                method: crate::scanner::host::DiscoveryMethod::Arp,
            })
            .collect();
        app.ports = (0..ports)
            .map(|i| PortResult {
                ip: std::net::Ipv4Addr::new(192, 168, 1, 1),
                port: i as u16,
                state: crate::scanner::port::PortState::Open,
                banner: None,
            })
            .collect();
        app
    }

    #[test]
    fn arrow_keys_move_whichever_table_has_focus() {
        let mut app = app_with(3, 5);

        app.scroll(1);
        assert_eq!(app.host_table_state.selected(), Some(0));
        assert_eq!(app.port_table_state.selected(), None);

        app.toggle_focus();
        app.scroll(1);
        assert_eq!(app.port_table_state.selected(), Some(0));
        assert_eq!(app.host_table_state.selected(), Some(0), "hosts moved too");
    }

    #[test]
    fn scrolling_clamps_at_both_ends() {
        let mut app = app_with(0, 4);
        app.focus = Pane::Ports;

        for _ in 0..10 {
            app.scroll(1);
        }
        assert_eq!(app.port_table_state.selected(), Some(3));

        for _ in 0..10 {
            app.scroll(-1);
        }
        assert_eq!(app.port_table_state.selected(), Some(0));
    }

    #[test]
    fn paging_up_from_nothing_enters_at_the_end() {
        let mut app = app_with(0, 20);
        app.focus = Pane::Ports;

        app.scroll(-10);
        assert_eq!(app.port_table_state.selected(), Some(19));
    }

    /// Results arrive while the user is reading, so the row they are on has to
    /// stay put.
    #[test]
    fn results_arriving_do_not_move_the_selection() {
        let mut app = app_with(0, 4);
        app.focus = Pane::Ports;
        app.scroll(1);
        app.scroll(1);
        assert_eq!(app.port_table_state.selected(), Some(1));

        app.ports.extend(app_with(0, 6).ports);
        assert_eq!(app.port_table_state.selected(), Some(1));
    }

    #[test]
    fn an_empty_table_selects_nothing() {
        let mut app = app_with(0, 0);
        app.focus = Pane::Ports;

        app.scroll(1);
        assert_eq!(app.port_table_state.selected(), None);
    }
}
