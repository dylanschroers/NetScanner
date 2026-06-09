use clap::ValueEnum;

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub target: String,
    pub ports: Vec<u16>,
    pub timeout_ms: u64,
    pub output_format: OutputFormat,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
}

pub fn parse_ports(input: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in input.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.trim().parse::<u16>(), end.trim().parse::<u16>()) {
                ports.extend(s..=e);
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }
    ports
}
