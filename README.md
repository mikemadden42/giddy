# giddy

A terminal UI that shows who's on your local network. No root required.

giddy runs several unprivileged discovery methods at the same time and merges what they find into one live device list:

| Method | What it does |
| --- | --- |
| **Subnet sweep** | Sends a tiny UDP datagram and a few TCP connection attempts to every address on the subnet. Before the kernel can send anything on the local link it has to resolve the target's MAC address, so this fills the ARP cache with every live host. Only ordinary sockets are used, with no raw packets. A TCP answer (open *or* refused) also proves a host is up. |
| **ARP cache** | Reads the kernel neighbor table (`ip neigh` / `/proc/net/arp` on Linux, `arp -an` on macOS/BSD, `arp -a` on Windows) once a second to map IPs to MAC addresses. |
| **mDNS / DNS-SD** | Sends queries from an ephemeral port ("legacy unicast", RFC 6762 §6.7), so responders reply directly without needing port 5353. It also joins 5353 alongside avahi/mDNSResponder when the OS allows, to hear announcements. Collects hostnames, friendly instance names (e.g. *Donna's iPhone*), services and models. |
| **SSDP / UPnP** | Sends `M-SEARCH` and fetches each device's description XML for its friendly name, manufacturer and model. Fetches are limited to addresses on the local subnet. |
| **Reverse DNS** | Asks the system resolver. Routers often know DHCP client names. |

Each MAC address is matched against the IEEE registry (MA-L, MA-M and MA-S, longest match wins) to show the manufacturer. Randomized "private" addresses, as used by modern phones, are labeled as such instead of being left blank.

## Usage

```sh
cargo run --release              # scan the interface with the default route
giddy -i wlan0                   # pick an interface
giddy --list-interfaces
giddy --interval 60              # seconds between discovery rounds (default 30)
giddy --no-sweep                 # passive-ish: mDNS, SSDP and existing ARP cache only
giddy --once                     # one round, print a plain-text table, exit
```

### Keys

| Key | Action |
| --- | --- |
| `↑` `↓` / `j` `k`, `PgUp` `PgDn`, `g` `G` | Navigate |
| `Enter` | Toggle the details panel (services, model, UPnP info, open ports…) |
| `/` | Filter by IP, name, MAC, manufacturer or model (`Esc` clears) |
| `s` / `S` | Cycle the sort column / reverse it |
| `a` | Give the device an alias (stored by MAC in `~/.config/giddy/aliases`) |
| `y` / `Y` | Copy IP / MAC to the clipboard (OSC 52, works over SSH) |
| `i` | Switch network interface |
| `r` | Rescan now |
| `?` | Help |
| `q` | Quit |

The **Via** column shows which methods saw each device: **A**RP, **M**DNS, **U**PnP/SSDP, **T**CP. Rows that haven't been seen recently are dimmed.

## Notes

- Large subnets are swept only within the /22 around your own address (1022 hosts).
- The manufacturer database is embedded in the binary. Run `scripts/update-oui.sh` to refresh `data/oui.tsv.gz` from Wireshark's `manuf` file.

## Acknowledgements

giddy was inspired by [whosthere](https://github.com/ramonvermeulen/whosthere) by Ramon Vermeulen, a LAN discovery tool with an interactive TUI written in Go. Its approach of combining mDNS, SSDP and an ARP-cache sweep without elevated privileges, and its device-list interface, shaped this project. giddy is an independent Rust implementation and shares no code with it. If you prefer Go, check out whosthere.

Manufacturer data comes from the IEEE registry, as compiled by the [Wireshark](https://www.wireshark.org/) project.
