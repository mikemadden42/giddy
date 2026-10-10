//! Application state and input handling.

use std::collections::HashMap;
use std::io::Write;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::widgets::TableState;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinHandle;

use crate::aliases::Aliases;
use crate::device::{Device, Sources};
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
    Alias(String),
    Interfaces(usize),
    Help,
}

#[derive(Default)]
pub struct ScanStatus {
    pub sweep: Option<(usize, usize)>,
    pub sweeping: bool,
    pub mdns: bool,
    pub ssdp: bool,
    pub netbios: bool,
    pub cycles: u32,
    pub next_at: Option<Instant>,
}

impl ScanStatus {
    pub fn busy(&self) -> bool {
        self.sweeping || self.mdns || self.ssdp || self.netbios
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

    pub fn current_iface(&self) -> &Iface {
        &self.ifaces[self.iface]
    }

    /// (Re)start discovery on the current interface.
    pub fn start_scan(&mut self) {
        if let Some(handle) = self.scanner.take() {
            handle.abort();
        }
        self.generation += 1;
        self.status = ScanStatus { cycles: self.status.cycles, ..Default::default() };
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
            ScanEvent::Banner { ip, banner } => device_entry(devices, iface, ip).apply_banner(&banner),
            ScanEvent::ReverseDns { ip, name } => device_entry(devices, iface, ip).rdns = Some(name),
            ScanEvent::SweepProgress { done, total } => self.status.sweep = Some((done, total)),
            ScanEvent::TaskStarted(task) | ScanEvent::TaskFinished(task) => {
                let running = matches!(ev, ScanEvent::TaskStarted(_));
                match task {
                    Task::Sweep => self.status.sweeping = running,
                    Task::Mdns => self.status.mdns = running,
                    Task::Ssdp => self.status.ssdp = running,
                    Task::NetBios => self.status.netbios = running,
                }
                if running {
                    self.status.next_at = None;
                }
            }
            ScanEvent::CycleFinished { next_in } => {
                self.status.cycles += 1;
                self.status.next_at = Some(Instant::now() + next_in);
            }
            ScanEvent::Error(msg) => self.toast(msg),
        }
    }

    fn apply_alias(&mut self, ip: Ipv4Addr) {
        if let Some(dev) = self.devices.get_mut(&ip) {
            dev.alias = dev.mac.and_then(|m| self.aliases.get(&m).cloned());
        }
    }

    /// Recompute the filtered/sorted view, keeping the selection on the same device.
    pub fn rebuild_view(&mut self) {
        let needle = self.filter.to_lowercase();
        let mut view: Vec<&Device> =
            self.devices.values().filter(|d| needle.is_empty() || matches_filter(d, &needle)).collect();
        view.sort_by(|a, b| {
            let ord = match self.sort {
                SortKey::Ip => a.ip.cmp(&b.ip),
                SortKey::Name => sort_text(a.display_name()).cmp(&sort_text(b.display_name())),
                // Unknown types sort last.
                SortKey::Type => (kind::classify(a).is_none(), kind::classify(a))
                    .cmp(&(kind::classify(b).is_none(), kind::classify(b))),
                SortKey::Manufacturer => sort_text(a.manufacturer()).cmp(&sort_text(b.manufacturer())),
                SortKey::LastSeen => b.last_seen.cmp(&a.last_seen),
            };
            let ord = if self.sort_desc { ord.reverse() } else { ord };
            ord.then(a.ip.cmp(&b.ip))
        });
        self.view = view.into_iter().map(|d| d.ip).collect();

        let idx = self
            .pinned
            .and_then(|ip| self.view.iter().position(|v| *v == ip))
            .or_else(|| (!self.view.is_empty()).then(|| self.table.selected().unwrap_or(0).min(self.view.len() - 1)));
        self.table.select(idx);
    }

    fn move_selection(&mut self, delta: isize) {
        if self.view.is_empty() {
            return;
        }
        let cur = self.table.selected().unwrap_or(0) as isize;
        let idx = (cur + delta).clamp(0, self.view.len() as isize - 1) as usize;
        self.table.select(Some(idx));
        self.pinned = Some(self.view[idx]);
    }

    pub fn on_terminal_event(&mut self, ev: Event) {
        let Event::Key(key) = ev else { return };
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
            Mode::Alias(input) => match key.code {
                KeyCode::Esc => self.mode = Mode::Normal,
                KeyCode::Backspace => {
                    input.pop();
                }
                KeyCode::Char(c) if !key.modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) => {
                    input.push(c)
                }
                KeyCode::Enter => {
                    let input = std::mem::take(input);
                    self.mode = Mode::Normal;
                    self.save_alias(&input);
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
            KeyCode::Home | KeyCode::Char('g') => self.move_selection(isize::MIN / 2),
            KeyCode::End | KeyCode::Char('G') => self.move_selection(isize::MAX / 2),
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
            KeyCode::Char('a') => match self.selected_device() {
                Some(d) if d.mac.is_some() => self.mode = Mode::Alias(d.alias.clone().unwrap_or_default()),
                Some(_) => self.toast("Can't alias a device without a known MAC address"),
                None => {}
            },
            KeyCode::Char('y') => {
                if let Some(ip) = self.selected_device().map(|d| d.ip) {
                    self.copy(ip.to_string());
                }
            }
            KeyCode::Char('Y') => {
                if let Some(mac) = self.selected_device().and_then(|d| d.mac) {
                    self.copy(mac.to_string());
                }
            }
            KeyCode::Char('?') => self.mode = Mode::Help,
            _ => {}
        }
    }

    fn save_alias(&mut self, input: &str) {
        let Some((ip, mac)) = self.selected_device().and_then(|d| Some((d.ip, d.mac?))) else { return };
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
    fn copy(&mut self, text: String) {
        let seq = format!("\x1b]52;c;{}\x07", base64(text.as_bytes()));
        let mut out = std::io::stdout();
        let _ = out.write_all(seq.as_bytes()).and_then(|_| out.flush());
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

/// Sort key that puts devices with no value last.
fn sort_text(s: Option<&str>) -> (bool, String) {
    (s.is_none(), s.unwrap_or_default().to_lowercase())
}

fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
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
    #[test]
    fn base64_matches_reference() {
        assert_eq!(super::base64(b""), "");
        assert_eq!(super::base64(b"f"), "Zg==");
        assert_eq!(super::base64(b"fo"), "Zm8=");
        assert_eq!(super::base64(b"foo"), "Zm9v");
        assert_eq!(super::base64(b"10.0.0.1"), "MTAuMC4wLjE=");
    }
}
