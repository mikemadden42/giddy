# giddy

[![CI](https://github.com/mikemadden42/giddy/actions/workflows/ci.yml/badge.svg)](https://github.com/mikemadden42/giddy/actions/workflows/ci.yml)

A terminal UI that shows who's on your local network. No root required.

giddy runs several unprivileged discovery methods at the same time and merges what they find into one live device list:

| Method | What it does |
| --- | --- |
| **Subnet sweep** | Sends a tiny UDP datagram and a few TCP connection attempts to every address on the subnet. Before the kernel can send anything on the local link it has to resolve the target's MAC address, so this fills the ARP cache with every live host. Only ordinary sockets are used, with no raw packets. A TCP answer (open *or* refused) also proves a host is up. |
| **ARP cache** | Reads the kernel neighbor table (`ip neigh` / `/proc/net/arp` on Linux, `sysctl` on macOS, `arp -an` on other BSDs, `arp -a` on Windows) once a second to map IPs to MAC addresses. |
| **mDNS / DNS-SD** | Sends queries from an ephemeral port ("legacy unicast", RFC 6762 §6.7), so responders reply directly without needing port 5353. It also joins 5353 alongside avahi/mDNSResponder when the OS allows, to hear announcements. Collects hostnames, friendly instance names (e.g. *iPhone*), services and models. |
| **SSDP / UPnP** | Sends `M-SEARCH` and fetches each device's description XML for its friendly name, manufacturer and model. Fetches are limited to addresses on the local subnet. |
| **NetBIOS** | After the sweep, sends a node-status query (UDP 137) to each host in the ARP cache. Windows PCs, Samba servers and NAS boxes reply with their hostname and workgroup. |
| **Service banners** | Reads what services say on connections the sweep already opened: the SSH version greeting on port 22, and the `Server` header, login realm and page title from an HTTP `GET /` on port 80. Each service is asked once per session. A login realm like `NETGEAR Orbi` often names a device that advertises nothing else. |
| **Reverse DNS** | Asks the system resolver. Routers often know DHCP client names. |

Each device also gets a best-guess **type** (router, phone, tv, printer, console…), inferred from what discovery already collected with no extra traffic. The rules check, in order: Apple hardware models (`AppleTV11,1`), advertised services (`_ipp` means a printer), UPnP device types, names (`iPhone`), open ports (62078 means an iOS device) and finally manufacturers that make only one kind of device (Nintendo). Devices that match no rule are left blank.

Each MAC address is matched against the IEEE registry (MA-L, MA-M and MA-S, longest match wins) to show the manufacturer. Randomized "private" addresses, as used by modern phones, are labeled as such instead of being left blank.

## Install

On Linux and Windows:

```sh
cargo install --path .           # or: cargo build --release
```

On macOS, use `make` instead of `cargo` directly:

```sh
make install                     # installs to ~/.cargo/bin/giddy
make                             # or just build target/release/giddy
```

macOS hides the ARP table from command-line tools unless their code signature names a bundle ID. A binary from a plain `cargo build` runs, but it finds fewer devices and shows no MAC addresses or manufacturers. `make` builds as usual and then re-signs the binary with the bundle ID from the embedded `macos/Info.plist`. The first time giddy runs, macOS asks whether it may find devices on your local network. Choose **Allow**.

## Usage

```sh
giddy                            # scan the interface with the default route
giddy -i wlan0                   # pick an interface
giddy --list-interfaces
giddy --interval 60              # seconds between discovery rounds (default 30)
giddy --no-sweep                 # passive-ish: mDNS, SSDP and existing ARP cache only
giddy --once                     # one round, print a plain-text table, exit
giddy --format json > scan.json  # one round as JSON (every detail; implies --once)
giddy --format csv > scan.csv    # one round as CSV, one row per device
```

Progress messages go to stderr, so redirected output stays clean. In JSON, every key is always present (`null` or `[]` when unknown), so tools like `jq` can rely on the shape:

```sh
giddy --format json | jq -r '.devices[] | select(.type == "printer") | .ip'
```

### Keys

| Key | Action |
| --- | --- |
| `↑` `↓` / `j` `k`, `PgUp` `PgDn`, `g` `G` | Navigate |
| `Enter` | Toggle the details panel (services, model, UPnP info, open ports…) |
| `/` | Filter by IP, name, MAC, manufacturer or model (`Esc` clears) |
| `s` / `S` | Cycle the sort column (IP, name, type, manufacturer, last seen) / reverse it |
| `a` | Give the device an alias (stored by MAC in `~/.config/giddy/aliases`) |
| `y` / `Y` | Copy IP / MAC to the clipboard (OSC 52, works over SSH) |
| `i` | Switch network interface |
| `r` | Rescan now |
| `?` | Help |
| `q` | Quit |

The **Via** column shows which methods saw each device: **A**RP, **M**DNS, **U**PnP/SSDP, **T**CP, **N**etBIOS. Rows that haven't been seen recently are dimmed.

## Notes

- Large subnets are swept only within the /22 around your own address (1022 hosts).
- The manufacturer database is embedded in the binary. Run `scripts/update-oui.sh` to refresh `data/oui.tsv.gz` from Wireshark's `manuf` file.

## Acknowledgements

giddy was inspired by [whosthere](https://github.com/ramonvermeulen/whosthere) by Ramon Vermeulen, a LAN discovery tool with an interactive TUI written in Go. Its approach of combining mDNS, SSDP and an ARP-cache sweep without elevated privileges, and its device-list interface, shaped this project. giddy is an independent Rust implementation and shares no code with it. If you prefer Go, check out whosthere.

Manufacturer data comes from the IEEE registry, as compiled by the [Wireshark](https://www.wireshark.org/) project.
