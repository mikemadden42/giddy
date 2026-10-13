//! Application state and input handling.

use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::widgets::TableState;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinHandle;

use crate::aliases::Aliases;
use crate::device::{Device, MacAddr, Sources};
use crate::iface::Iface;
use crate::kind;
use crate::scan::{self, ScanEvent, Tagged, Task};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    Ip,
    Name,
    Type,
    Manufacturer,
    LastSeen,
}

impl SortKey {
    pub fn label(self) -> &'static str {
        match self {
            SortKey::Ip => "IP",
            SortKey::Name => "name",
            SortKey::Type => "type",
            SortKey::Manufacturer => "manufacturer",
            SortKey::LastSeen => "last seen",
        }
    }

    fn next(self) -> Self {
        match self {
            SortKey::Ip => SortKey::Name,
            SortKey::Name => SortKey::Type,
            SortKey::Type => SortKey::Manufacturer,
            SortKey::Manufacturer => SortKey::LastSeen,
            SortKey::LastSeen => SortKey::Ip,
        }
    }
}

pub enum Mode {
    Normal,
    Filter,
    /// Naming a device. Its MAC and IP are captured when the prompt opens,
    /// since rows can move under the cursor while the user types.
    Alias {
        mac: MacAddr,
        ip: Ipv4Addr,
        input: String,
    },
    Interfaces(usize),
    Help,
}

#[derive(Default)]
pub struct ScanStatus {
    pub sweep: Option<(usize, usize)>,
    /// Discovery tasks currently in progress.
    pub running: BTreeSet<Task>,
    pub cycles: u32,
    pub next_at: Option<Instant>,
    /// When the current discovery cycle began (scan start, or the end of
    /// the previous cycle), and how long the last full cycle took, wait
    /// included. A /16 sweep makes cycles minutes long.
    pub cycle_started: Option<Instant>,
    pub last_cycle: Duration,
}

impl ScanStatus {
    pub fn busy(&self) -> bool {
        !self.running.is_empty()
    }
}

pub struct App {
    pub ifaces: Vec<Iface>,
    pub iface: usize,
    pub devices: HashMap<Ipv4Addr, Device>,
    /// Filtered, sorted device IPs as displayed.
    pub view: Vec<Ipv4Addr>,
    pub table: TableState,
    pub sort: SortKey,
    pub sort_desc: bool,
    pub filter: String,
    pub mode: Mode,
    pub details: bool,
    pub status: ScanStatus,
    pub toast: Option<(String, Instant)>,
    pub cfg: scan::Config,
    pub quit: bool,
    pub frame: usize,
    aliases: Aliases,
    /// Device the user navigated to; the selection follows it across
    /// re-sorts. Until they move, the selection stays at the top.
    pinned: Option<Ipv4Addr>,
    generation: u64,
    scanner: Option<JoinHandle<()>>,
    out: UnboundedSender<Tagged>,
}

impl App {
    pub fn new(ifaces: Vec<Iface>, iface: usize, cfg: scan::Config, out: UnboundedSender<Tagged>) -> Self {
        App {
            ifaces,
            iface,
            devices: HashMap::new(),
            view: Vec::new(),
            table: TableState::default(),
            sort: SortKey::Ip,
            sort_desc: false,
            filter: String::new(),
            mode: Mode::Normal,
            details: false,
            status: ScanStatus::default(),
            toast: None,
            cfg,
            quit: false,
            frame: 0,
            aliases: Aliases::load(),
            pinned: None,
            generation: 0,
            scanner: None,
            out,
        }
    }

    /// How long a device can go unseen before its row is dimmed. At least
    /// one and a half discovery cycles, so a long sweep (e.g. `--sweep` over a
    /// /16) doesn't dim devices it just hasn't reached again yet.
    pub fn stale_after(&self) -> Duration {
        let base = (self.cfg.interval * 3).max(Duration::from_secs(90));
        let current = self.status.cycle_started.map(|t| t.elapsed()).unwrap_or_default();
        base.max(self.status.last_cycle.max(current) * 3 / 2)
    }

    pub fn current_iface(&self) -> &Iface {
        &self.ifaces[self.iface]
    }

    /// (Re)start discovery on the current interface.
    pub fn start_scan(&mut self) {
        if let Some(handle) = self.scanner.take() {
            handle.abort();
        }
        self.generation += 1;
        self.status =
            ScanStatus { cycles: self.status.cycles, cycle_started: Some(Instant::now()), ..Default::default() };
        let iface = self.current_iface().clone();
        self.add_self(&iface);
        let fut = scan::run(iface, self.cfg.clone(), self.generation, self.out.clone());
        self.scanner = Some(tokio::spawn(fut));
    }

    fn add_self(&mut self, iface: &Iface) {
        let dev = self.devices.entry(iface.ip).or_insert_with(|| Device::new(iface.ip));
        dev.is_self = true;
        if let Some(mac) = iface.mac {
            dev.set_mac(mac);
        }
        if dev.rdns.is_none() {
            dev.rdns = dns_lookup::get_hostname().ok();
        }
        self.apply_alias(iface.ip);
        self.rebuild_view();
    }

    fn switch_iface(&mut self, idx: usize) {
        if idx != self.iface {
            self.iface = idx;
            self.devices.clear();
            self.table.select(None);
            self.pinned = None;
        }
        self.start_scan();
        self.toast(format!("Scanning {} ({})", self.current_iface().name, self.current_iface().cidr()));
    }

    pub fn selected_device(&self) -> Option<&Device> {
        let ip = self.view.get(self.table.selected()?)?;
        self.devices.get(ip)
    }

    pub fn toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now()));
    }

    pub fn on_tick(&mut self) {
        self.frame = self.frame.wrapping_add(1);
        if self.toast.as_ref().is_some_and(|(_, at)| at.elapsed() > Duration::from_secs(4)) {
            self.toast = None;
        }
        // We know we're alive; keep our own row fresh.
        let me = self.current_iface().ip;
        if let Some(dev) = self.devices.get_mut(&me) {
            dev.touch();
        }
        if self.sort == SortKey::LastSeen {
            self.rebuild_view();
        }
    }

    pub fn on_scan(&mut self, (generation, ev): Tagged) {
        if generation != self.generation {
            return;
        }
        let stale_after = self.stale_after();
        let iface = &self.ifaces[self.iface];
        let devices = &mut self.devices;
        match ev {
            ScanEvent::Neighbor { ip, mac, active } => {
                let dev = device_entry(devices, iface, ip);
                let new = !dev.sources.contains(Sources::ARP) || dev.mac != Some(mac);
                dev.sources.insert(Sources::ARP);
                dev.set_mac(mac);
                if active || new {
                    dev.touch();
                    for old in superseded(devices, ip, mac, stale_after) {
                        devices.remove(&old);
                    }
                }
                self.apply_alias(ip);
            }
            ScanEvent::Alive { ip, open_port } => {
                let dev = device_entry(devices, iface, ip);
                dev.sources.insert(Sources::TCP);
                dev.open_ports.extend(open_port);
                dev.touch();
            }
            ScanEvent::Mdns(rec) => device_entry(devices, iface, rec.ip).apply_mdns(&rec),
            ScanEvent::Ssdp(rec) => device_entry(devices, iface, rec.ip).apply_ssdp(&rec),
            ScanEvent::SsdpDescription(desc) => device_entry(devices, iface, desc.ip).apply_ssdp_description(&desc),
            ScanEvent::NetBios(rec) => device_entry(devices, iface, rec.ip).apply_netbios(&rec),
            // Late answers for a row that's since been pruned shouldn't bring it back.
            ScanEvent::Banner { ip, banner } => {
                if let Some(dev) = devices.get_mut(&ip) {
                    dev.apply_banner(&banner);
                }
            }
            ScanEvent::ReverseDns { ip, name } => {
                if let Some(dev) = devices.get_mut(&ip) {
                    dev.rdns = Some(name);
                }
            }
            ScanEvent::SweepProgress { done, total } => self.status.sweep = Some((done, total)),
            ScanEvent::TaskStarted(task) | ScanEvent::TaskFinished(task) => {
                let running = matches!(ev, ScanEvent::TaskStarted(_));
                if running {
                    self.status.running.insert(task);
                } else {
                    self.status.running.remove(&task);
                }
                if running {
                    self.status.next_at = None;
                }
            }
            ScanEvent::CycleFinished { next_in } => {
                self.status.cycles += 1;
                self.status.next_at = Some(Instant::now() + next_in);
                if let Some(started) = self.status.cycle_started {
                    // Count the wait before the next cycle too.
                    self.status.last_cycle = started.elapsed() + next_in;
                }
                self.status.cycle_started = Some(Instant::now() + next_in);
            }
            ScanEvent::Error(msg) => self.toast(msg),
        }
    }

    fn apply_alias(&mut self, ip: Ipv4Addr) {
        if let Some(dev) = self.devices.get_mut(&ip) {
            dev.alias = dev.mac.and_then(|m| self.aliases.get(m).cloned());
        }
    }

    /// Recompute the filtered/sorted view, keeping the selection on the same device.
    pub fn rebuild_view(&mut self) {
        let needle = self.filter.to_lowercase();
        // Work out each device's sort value once, not on every comparison:
        // classifying a device's type builds strings.
        let mut view: Vec<(SortValue, Ipv4Addr)> = self
            .devices
            .values()
            .filter(|d| needle.is_empty() || matches_filter(d, &needle))
            .map(|d| (SortValue::of(self.sort, d), d.ip))
            .collect();
        view.sort_by(|(a, a_ip), (b, b_ip)| {
            let ord = a.cmp(b);
            let ord = if self.sort_desc { ord.reverse() } else { ord };
            ord.then(a_ip.cmp(b_ip))
        });
        self.view = view.into_iter().map(|(_, ip)| ip).collect();

        let idx = self
            .pinned
            .and_then(|ip| self.view.iter().position(|v| *v == ip))
            .or_else(|| (!self.view.is_empty()).then(|| self.table.selected().unwrap_or(0).min(self.view.len() - 1)));
        self.table.select(idx);
    }

    fn move_selection(&mut self, delta: isize) {
        let cur = self.table.selected().unwrap_or(0);
        self.select(cur.saturating_add_signed(delta));
    }

    /// Select row `idx` (clamped to the list) and pin that device.
    fn select(&mut self, idx: usize) {
        let Some(last) = self.view.len().checked_sub(1) else { return };
        let idx = idx.min(last);
        self.table.select(Some(idx));
        self.pinned = Some(self.view[idx]);
    }

    pub fn on_terminal_event(&mut self, ev: &Event) {
        let &Event::Key(key) = ev else { return };
        if key.kind != KeyEventKind::Press {
            return;
        }
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.quit = true;
            return;
        }
        match &mut self.mode {
            Mode::Normal => self.on_normal_key(key),
            Mode::Help => self.mode = Mode::Normal,
            Mode::Filter => match key.code {
                KeyCode::Esc => {
                    self.filter.clear();
                    self.mode = Mode::Normal;
                    self.rebuild_view();
                }
                KeyCode::Enter | KeyCode::Down | KeyCode::Up => self.mode = Mode::Normal,
                KeyCode::Backspace => {
                    self.filter.pop();
                    self.rebuild_view();
                }
                KeyCode::Char(c) if !key.modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) => {
                    self.filter.push(c);
                    self.rebuild_view();
                }
                _ => {}
            },
            Mode::Alias { mac, ip, input } => match key.code {
                KeyCode::Esc => self.mode = Mode::Normal,
                KeyCode::Backspace => {
                    input.pop();
                }
                KeyCode::Char(c) if !key.modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) => {
                    input.push(c);
                }
                KeyCode::Enter => {
                    let (mac, ip, input) = (*mac, *ip, std::mem::take(input));
                    self.mode = Mode::Normal;
                    self.save_alias(mac, ip, &input);
                }
                _ => {}
            },
            Mode::Interfaces(cursor) => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => self.mode = Mode::Normal,
                KeyCode::Down | KeyCode::Char('j') => *cursor = (*cursor + 1).min(self.ifaces.len() - 1),
                KeyCode::Up | KeyCode::Char('k') => *cursor = cursor.saturating_sub(1),
                KeyCode::Enter => {
                    let idx = *cursor;
                    self.mode = Mode::Normal;
                    self.switch_iface(idx);
                }
                _ => {}
            },
        }
    }

    fn on_normal_key(&mut self, key: KeyEvent) {
        let page = 10;
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Esc if !self.filter.is_empty() => {
                self.filter.clear();
                self.rebuild_view();
            }
            KeyCode::Esc if self.details => self.details = false,
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::PageDown => self.move_selection(page),
            KeyCode::PageUp => self.move_selection(-page),
            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => self.move_selection(page),
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => self.move_selection(-page),
            KeyCode::Home | KeyCode::Char('g') => self.select(0),
            KeyCode::End | KeyCode::Char('G') => self.select(usize::MAX),
            KeyCode::Enter | KeyCode::Char(' ') => self.details = !self.details,
            KeyCode::Char('/') => self.mode = Mode::Filter,
            KeyCode::Char('s') => {
                self.sort = self.sort.next();
                self.sort_desc = false;
                self.rebuild_view();
                self.toast(format!("Sorted by {}", self.sort.label()));
            }
            KeyCode::Char('S') => {
                self.sort_desc = !self.sort_desc;
                self.rebuild_view();
            }
            KeyCode::Char('r') => {
                self.start_scan();
                self.toast("Rescanning…");
            }
            KeyCode::Char('i') => self.mode = Mode::Interfaces(self.iface),
            KeyCode::Char('a') => {
                if let Some(d) = self.selected_device() {
                    match d.mac {
                        Some(mac) => {
                            self.mode = Mode::Alias { mac, ip: d.ip, input: d.alias.clone().unwrap_or_default() };
                        }
                        None => self.toast("Can't alias a device without a known MAC address"),
                    }
                }
            }
            KeyCode::Char('y') => {
                if let Some(ip) = self.selected_device().map(|d| d.ip) {
                    self.copy(&ip.to_string());
                }
            }
            KeyCode::Char('Y') => {
                if let Some(mac) = self.selected_device().and_then(|d| d.mac) {
                    self.copy(&mac.to_string());
                }
            }
            KeyCode::Char('?') => self.mode = Mode::Help,
            _ => {}
        }
    }

    fn save_alias(&mut self, mac: MacAddr, ip: Ipv4Addr, input: &str) {
        match self.aliases.set(mac, input) {
            Ok(()) => self.toast(if input.trim().is_empty() { "Alias cleared" } else { "Alias saved" }),
            Err(e) => self.toast(format!("Couldn't save alias: {e}")),
        }
        // A MAC can appear at several IPs (e.g. a router); update them all.
        let ips: Vec<_> = self.devices.values().filter(|d| d.mac == Some(mac)).map(|d| d.ip).collect();
        for other in ips.into_iter().chain([ip]) {
            self.apply_alias(other);
        }
        self.rebuild_view();
    }

    /// Copy to the system clipboard via the OSC 52 terminal escape, which
    /// works locally and over SSH in most modern terminals.
    fn copy(&mut self, text: &str) {
        let seq = format!("\x1b]52;c;{}\x07", base64(text.as_bytes()));
        let mut out = std::io::stdout();
        let _ = out.write_all(seq.as_bytes()).and_then(|()| out.flush());
        self.toast(format!("Copied {text}"));
    }
}

fn device_entry<'a>(devices: &'a mut HashMap<Ipv4Addr, Device>, iface: &Iface, ip: Ipv4Addr) -> &'a mut Device {
    devices.entry(ip).or_insert_with(|| {
        let mut d = Device::new(ip);
        d.is_gateway = iface.gateway == Some(ip);
        d.is_self = ip == iface.ip;
        d
    })
}

/// Rows left behind when a device moves to a new address (e.g. a phone that
/// rejoins Wi-Fi and gets a new DHCP lease): other IPs with the same MAC that
/// have already gone stale. Live ones are kept, since a router can legitimately
/// answer for several addresses.
fn superseded(devices: &HashMap<Ipv4Addr, Device>, ip: Ipv4Addr, mac: MacAddr, stale_after: Duration) -> Vec<Ipv4Addr> {
    devices
        .values()
        .filter(|d| d.ip != ip && d.mac == Some(mac) && !d.is_self && !d.is_gateway)
        .filter(|d| d.last_seen.elapsed() > stale_after)
        .map(|d| d.ip)
        .collect()
}

fn matches_filter(d: &Device, needle: &str) -> bool {
    let mac = d.mac.map(|m| m.to_string());
    [
        Some(d.ip.to_string().as_str()),
        d.display_name(),
        mac.as_deref(),
        d.manufacturer(),
        d.model(),
        d.mdns_host.as_deref(),
        d.rdns.as_deref(),
        d.netbios_name.as_deref(),
        d.web_label(),
        kind::classify(d).map(kind::Kind::label),
        d.http.as_ref().and_then(|h| h.server.as_deref()),
        d.ssh_banner.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|s| s.to_lowercase().contains(needle))
}

/// A device's value for the current sort column. Missing values sort last.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum SortValue {
    Ip(Ipv4Addr),
    Text(bool, String),
    Kind(bool, Option<kind::Kind>),
    Seen(std::cmp::Reverse<Instant>),
}

impl SortValue {
    fn of(key: SortKey, d: &Device) -> Self {
        let text = |s: Option<&str>| SortValue::Text(s.is_none(), s.unwrap_or_default().to_lowercase());
        match key {
            SortKey::Ip => SortValue::Ip(d.ip),
            SortKey::Name => text(d.display_name()),
            SortKey::Manufacturer => text(d.manufacturer()),
            SortKey::Type => {
                let k = kind::classify(d);
                SortValue::Kind(k.is_none(), k)
            }
            // Most recent first.
            SortKey::LastSeen => SortValue::Seen(std::cmp::Reverse(d.last_seen)),
        }
    }
}

fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    use crate::device::{Device, MacAddr};

    #[test]
    fn superseded_drops_only_stale_rows_with_same_mac() {
        let mac = MacAddr([0x02, 0, 0, 0, 0, 0x01]);
        let other = MacAddr([0x02, 0, 0, 0, 0, 0x02]);
        let long_ago = Instant::now().checked_sub(Duration::from_secs(3600)).unwrap();
        let mut devices = HashMap::new();
        let mut add = |last: u8, mac: MacAddr, seen: Instant| {
            let ip = Ipv4Addr::new(10, 0, 0, last);
            let mut d = Device::new(ip);
            d.mac = Some(mac);
            d.last_seen = seen;
            devices.insert(ip, d);
        };
        add(110, mac, Instant::now()); // the device's current address
        add(104, mac, long_ago); // old lease: dropped
        add(107, mac, Instant::now()); // still live: kept
        add(101, other, long_ago); // different device: kept
        let mut old = super::superseded(&devices, Ipv4Addr::new(10, 0, 0, 110), mac, Duration::from_secs(90));
        old.sort();
        assert_eq!(old, [Ipv4Addr::new(10, 0, 0, 104)]);
    }

    fn app() -> super::App {
        let iface =
            crate::iface::Iface { name: "t".into(), ip: [10, 0, 0, 2].into(), prefix: 24, mac: None, gateway: None };
        let cfg = crate::scan::Config { interval: Duration::from_secs(30), sweep: true, rate: 500, range: None };
        super::App::new(vec![iface], 0, cfg, tokio::sync::mpsc::unbounded_channel().0)
    }

    #[test]
    fn long_cycles_stretch_the_dimming_threshold() {
        let mut app = app();
        assert_eq!(app.stale_after(), Duration::from_secs(90)); // a quick /24 cycle
        app.status.last_cycle = Duration::from_secs(200); // e.g. a /16 sweep plus the wait
        assert_eq!(app.stale_after(), Duration::from_secs(300));
        // A first cycle still running counts too.
        app.status.last_cycle = Duration::ZERO;
        app.status.cycle_started = Instant::now().checked_sub(Duration::from_secs(120));
        assert!(app.stale_after() >= Duration::from_secs(180));
    }

    #[test]
    fn late_answers_do_not_recreate_rows() {
        use crate::scan::ScanEvent;
        let mut app = app();
        let ip = Ipv4Addr::new(10, 0, 0, 9);
        app.on_scan((0, ScanEvent::ReverseDns { ip, name: "old".into() }));
        assert!(!app.devices.contains_key(&ip));
        app.devices.insert(ip, Device::new(ip));
        app.on_scan((0, ScanEvent::ReverseDns { ip, name: "printer".into() }));
        assert_eq!(app.devices[&ip].rdns.as_deref(), Some("printer"));
    }

    #[test]
    fn sort_orders() {
        use super::SortKey;
        let mut app = app();
        app.devices.clear();
        let now = Instant::now();
        let mut add = |last: u8, host: Option<&str>, ago: u64| {
            let ip = Ipv4Addr::new(10, 0, 0, last);
            let mut d = Device::new(ip);
            d.mdns_host = host.map(String::from);
            d.last_seen = now.checked_sub(Duration::from_secs(ago)).unwrap();
            app.devices.insert(ip, d);
        };
        add(3, Some("kitchen-ipad"), 5); // tablet
        add(1, None, 50); // no type, no name
        add(2, Some("guest-iphone"), 1); // phone
        let order = |app: &super::App| app.view.iter().map(|ip| ip.octets()[3]).collect::<Vec<_>>();

        app.sort = SortKey::Ip;
        app.rebuild_view();
        assert_eq!(order(&app), [1, 2, 3]);
        app.sort = SortKey::Name; // unnamed last
        app.rebuild_view();
        assert_eq!(order(&app), [2, 3, 1]);
        app.sort = SortKey::Type; // phone < tablet, unknown last
        app.rebuild_view();
        assert_eq!(order(&app), [2, 3, 1]);
        app.sort_desc = true;
        app.rebuild_view();
        assert_eq!(order(&app), [1, 3, 2]);
        app.sort_desc = false;
        app.sort = SortKey::LastSeen; // most recent first
        app.rebuild_view();
        assert_eq!(order(&app), [2, 3, 1]);
    }

    #[test]
    fn base64_matches_reference() {
        assert_eq!(super::base64(b""), "");
        assert_eq!(super::base64(b"f"), "Zg==");
        assert_eq!(super::base64(b"fo"), "Zm8=");
        assert_eq!(super::base64(b"foo"), "Zm9v");
        assert_eq!(super::base64(b"10.0.0.1"), "MTAuMC4wLjE=");
    }
}
