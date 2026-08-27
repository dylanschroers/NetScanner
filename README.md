# NetScanner

A lightweight network scanner built in Rust. Designed for local network reconnaissance with a live terminal UI, minimal dependencies, and no external tools required.

---

## Requirements

- Rust (stable)
- Raw socket access — required for ARP, ICMP and passive capture. See [Granting capture rights](#granting-capture-rights).

---

## Building

```bash
cargo build --release
```

## Running

```bash
cargo build && sudo ./target/debug/netscanner
```

The tool launches an interactive menu on startup. No flags required.

Prefer this over `sudo cargo run`, which compiles as root and leaves root-owned
artifacts in `target/` that later unprivileged builds cannot overwrite.

### Granting capture rights

Rather than reaching for `sudo` on every run, grant the built binary the one
capability it needs:

```bash
sudo setcap cap_net_raw+ep ./target/debug/netscanner
```

`CAP_NET_RAW` is the whole requirement — it permits opening the `AF_PACKET`
socket and putting it in promiscuous mode. Nothing here reconfigures an
interface, so `CAP_NET_ADMIN` is not needed.

`cargo run` then works unprivileged. The grant applies to the file, not the
project, so re-run it after each rebuild. To check or remove it:

```bash
getcap ./target/debug/netscanner
sudo setcap -r ./target/debug/netscanner
```

`./run.sh` does the build, the grant and the launch in one step.

To keep the grant across rebuilds, install to a path cargo does not overwrite:

```bash
cargo install --path .
sudo setcap cap_net_raw+ep ~/.cargo/bin/netscanner
```

Without either, the menu says so before you pick an interface, and repeats the
exact command to run. Nothing is silently empty.

On Windows this is Npcap instead: install it, and run NetScanner as
Administrator.

---

## Usage

On launch you are presented with a mode selection screen. Use `↑↓` to choose a mode and `Enter` to confirm.

### Active Scan

Actively probes the network by sending packets to discover hosts and open ports.

- Enter a target IP or CIDR range (e.g. `192.168.1.1` or `192.168.1.0/24`)
- Enter a port range or list (e.g. `1-1024` or `22,80,443`)
- Host discovery uses ARP on local subnets, ICMP ping for remote targets
- Port scanning uses async TCP connect across all live hosts concurrently
- Banner grabbing runs automatically on each open port to identify the service and version

### Passive Scan

Puts your network interface into promiscuous mode and listens silently — no packets are sent.

- Enter your network interface name (e.g. `en0`)
- Discovers hosts from observed ARP broadcasts
- Logs DNS queries made by devices on the network
- Extracts hostnames and vendor class IDs from DHCP requests
- Logs TCP SYN connections initiated by other devices
- The host map builds up over time as devices naturally generate traffic

### Navigation

| Key | Action |
|-----|--------|
| `↑↓` | Select mode / scroll host list |
| `Enter` | Confirm |
| `Esc` | Return to main menu |
| `Tab` | Next input field (active scan setup) |
| `q` | Quit |

---

## Architecture

```
src/
├── main.rs           # Entry point and main loop
├── config.rs         # Typed scan configuration
├── packet/
│   ├── arp.rs        # ARP request/reply construction
│   ├── icmp.rs       # ICMP echo request/reply construction
│   └── tcp.rs        # Raw TCP SYN packet construction
├── scanner/
│   ├── host.rs       # Host discovery orchestration
│   ├── port.rs       # Async TCP port scanner
│   └── banner.rs     # Service banner grabbing
├── passive/
│   ├── mod.rs        # Promiscuous capture loop
│   ├── arp.rs        # ARP frame parser
│   ├── dns.rs        # DNS query/response parser
│   ├── dhcp.rs       # DHCP option parser
│   └── tcp.rs        # TCP flag observer
├── output/
│   ├── table.rs      # Terminal table output (comfy-table)
│   └── json.rs       # JSON export (serde_json)
└── tui/
    ├── app.rs        # TUI application state
    ├── ui.rs         # Active scan layout and widgets
    ├── passive.rs    # Passive scan layout and widgets
    └── menu.rs       # Startup menu and mode selection
```

### Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime and concurrent port scanning |
| `pnet` | Raw packet crafting and promiscuous capture |
| `ratatui` | Terminal UI framework |
| `crossterm` | Cross-platform terminal input/output |
| `clap` | CLI argument parsing |
| `serde` / `serde_json` | JSON serialization |
| `comfy-table` | Table formatting |
| `cidr` | CIDR subnet parsing |

---

## Planned Features

- **OS fingerprinting** — infer operating system from TCP/IP stack behavior (TTL, window size, options)
- **UDP scanning** — detect open UDP services alongside TCP
- **Raw SYN scanning** — faster, stealthier port scanning using raw TCP SYN packets instead of full connect (root only)
- **Service detection** — match banners against a known service signature database
- **Scrollable ports table** — keyboard navigation for the open ports list, mirroring host list scrolling
- **Export to file** — save scan results to JSON or CSV directly from the TUI
- **Passive + active hybrid mode** — start passive to silently build a host map, then selectively active-scan chosen hosts
- **Port mirroring support** — configure a SPAN port on a managed switch for full passive traffic capture
- **Scheduled scans** — run recurring scans and diff results to detect new devices or changed services
- **IPv6 support** — neighbor discovery and port scanning over IPv6

---

## Notes

- ARP scanning only works on local subnets. Remote targets fall back to ICMP.
- Passive mode is limited on switched networks — you will only see broadcast traffic and traffic addressed to your machine. Devices that have not sent any traffic since capture started will not appear until they do.
- iOS and some Android devices suppress ARP responses when the screen is off. Wake the device screen if it does not appear during an active scan.
- Raw socket operations require root or `CAP_NET_RAW`. Without them the passive
  screen reports the failure and the remedy rather than showing an empty table.
- DHCP identifies a client by MAC before it has an address, so hostnames learned
  from DHCP are matched to hosts by MAC, not IP.
