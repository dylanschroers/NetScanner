mod config;
mod output;
mod packet;
mod passive;
mod scanner;
mod tui;

use cidr::Ipv4Cidr;
use config::{OutputFormat, ScanConfig, parse_ports};
use std::net::Ipv4Addr;
use std::str::FromStr;
use tui::menu::{MenuResult, run as run_menu};
use tui::ScanExit;

#[tokio::main]
async fn main() {
    loop {
        let choice = match run_menu() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Menu error: {e}");
                std::process::exit(1);
            }
        };

        match choice {
            MenuResult::Quit => break,

            MenuResult::Passive { interface } => {
                match tui::passive::run(&interface) {
                    Ok(ScanExit::BackToMenu) => continue,
                    Ok(ScanExit::Quit)       => break,
                    Err(e) => {
                        eprintln!("Passive capture error: {e}");
                        std::process::exit(1);
                    }
                }
            }

            MenuResult::Active { target, ports, timeout } => {
                let targets = resolve_targets(&target);
                if targets.is_empty() {
                    eprintln!("Error: could not parse target '{}'", target);
                    std::process::exit(1);
                }

                let config = ScanConfig {
                    target: target.clone(),
                    ports: parse_ports(&ports),
                    timeout_ms: timeout,
                    output_format: OutputFormat::Table,
                };

                match tui::run(&config, targets).await {
                    Ok(ScanExit::BackToMenu) => continue,
                    Ok(ScanExit::Quit)       => break,
                    Err(e) => {
                        eprintln!("Scanner error: {e}");
                        std::process::exit(1);
                    }
                }
            }
        }
    }
}

fn resolve_targets(target: &str) -> Vec<Ipv4Addr> {
    if let Ok(cidr) = Ipv4Cidr::from_str(target) {
        cidr.iter().map(|inet| inet.address()).collect()
    } else if let Ok(ip) = Ipv4Addr::from_str(target) {
        vec![ip]
    } else {
        vec![]
    }
}
