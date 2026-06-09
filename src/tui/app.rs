use ratatui::widgets::TableState;
use crate::scanner::{host::HostResult, port::PortResult};

pub enum ScanState {
    Discovering,
    Scanning,
    Done,
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
    pub host_table_state: TableState,
}

impl App {
    pub fn new(target: String, total_hosts: usize, total_ports: usize) -> Self {
        let mut host_table_state = TableState::default();
        host_table_state.select(None);
        Self {
            target,
            total_hosts,
            total_ports,
            hosts: Vec::new(),
            ports: Vec::new(),
            scanned_ports: 0,
            state: ScanState::Discovering,
            should_quit: false,
            host_table_state,
        }
    }

    pub fn progress(&self) -> f64 {
        if self.total_ports == 0 {
            return 1.0;
        }
        self.scanned_ports as f64 / self.total_ports as f64
    }

    pub fn scroll_hosts_down(&mut self) {
        if self.hosts.is_empty() {
            return;
        }
        let next = match self.host_table_state.selected() {
            Some(i) => (i + 1).min(self.hosts.len() - 1),
            None    => 0,
        };
        self.host_table_state.select(Some(next));
    }

    pub fn scroll_hosts_up(&mut self) {
        if self.hosts.is_empty() {
            return;
        }
        let next = match self.host_table_state.selected() {
            Some(0) | None => 0,
            Some(i)        => i - 1,
        };
        self.host_table_state.select(Some(next));
    }
}
