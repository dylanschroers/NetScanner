use serde::Serialize;
use crate::scanner::{host::HostResult, port::PortResult};

#[derive(Serialize)]
struct JsonHost<'a> {
    ip: String,
    mac: Option<&'a str>,
    method: String,
}

#[derive(Serialize)]
struct JsonPort<'a> {
    ip: String,
    port: u16,
    state: &'static str,
    banner: Option<&'a str>,
}

#[derive(Serialize)]
struct JsonOutput<'a> {
    hosts: Vec<JsonHost<'a>>,
    ports: Vec<JsonPort<'a>>,
}

pub fn render(hosts: &[HostResult], ports: &[PortResult]) {
    let output = JsonOutput {
        hosts: hosts.iter().map(|h| JsonHost {
            ip: h.ip.to_string(),
            mac: h.mac.as_deref(),
            method: format!("{:?}", h.method),
        }).collect(),
        ports: ports.iter().map(|p| JsonPort {
            ip: p.ip.to_string(),
            port: p.port,
            state: "open",
            banner: p.banner.as_deref(),
        }).collect(),
    };

    match serde_json::to_string_pretty(&output) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("JSON serialization error: {e}"),
    }
}
