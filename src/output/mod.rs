pub mod json;
pub mod table;

use crate::config::OutputFormat;
use crate::scanner::{host::HostResult, port::PortResult};

pub fn render(format: &OutputFormat, hosts: &[HostResult], ports: &[PortResult]) {
    match format {
        OutputFormat::Table => table::render(hosts, ports),
        OutputFormat::Json  => json::render(hosts, ports),
    }
}
