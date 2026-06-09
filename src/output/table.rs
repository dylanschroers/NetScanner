use comfy_table::{Table, Cell, Color, Attribute, presets::UTF8_FULL};
use crate::scanner::{host::HostResult, port::PortResult};

pub fn render(hosts: &[HostResult], ports: &[PortResult]) {
    print_host_table(hosts);
    println!();
    print_port_table(ports);
}

fn print_host_table(hosts: &[HostResult]) {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        Cell::new("IP Address").add_attribute(Attribute::Bold),
        Cell::new("MAC Address").add_attribute(Attribute::Bold),
        Cell::new("Method").add_attribute(Attribute::Bold),
    ]);

    if hosts.is_empty() {
        table.add_row(vec!["No hosts found", "", ""]);
    } else {
        for host in hosts {
            table.add_row(vec![
                Cell::new(&host.ip.to_string()).fg(Color::Cyan),
                Cell::new(host.mac.as_deref().unwrap_or("—")),
                Cell::new(format!("{:?}", host.method)),
            ]);
        }
    }

    println!("  Hosts");
    println!("{table}");
}

fn print_port_table(ports: &[PortResult]) {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        Cell::new("IP Address").add_attribute(Attribute::Bold),
        Cell::new("Port").add_attribute(Attribute::Bold),
        Cell::new("State").add_attribute(Attribute::Bold),
        Cell::new("Banner").add_attribute(Attribute::Bold),
    ]);

    if ports.is_empty() {
        table.add_row(vec!["No open ports found", "", "", ""]);
    } else {
        for port in ports {
            table.add_row(vec![
                Cell::new(&port.ip.to_string()).fg(Color::Cyan),
                Cell::new(port.port.to_string()).fg(Color::Yellow),
                Cell::new("open").fg(Color::Green),
                Cell::new(port.banner.as_deref().unwrap_or("—")),
            ]);
        }
    }

    println!("  Open Ports");
    println!("{table}");
}
