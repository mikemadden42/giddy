//! The device model and how scanner observations merge into it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Instant;

use crate::oui;
use crate::scan::{MdnsRecord, SsdpDescription, SsdpRecord};

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// Locally administered addresses (e.g. randomized "private" Wi-Fi
    /// addresses on phones) have no registered manufacturer.
    pub fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 6]
    }

    pub fn is_broadcast_or_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2], b[3], b[4], b[5])
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for MacAddr {
    type Err = ();

    /// Accepts `aa:bb:cc:dd:ee:ff`, `aa-bb-…`, and the zero-stripped form
    /// some `arp` implementations print (`0:1b:…`).
    fn from_str(s: &str) -> Result<Self, ()> {
        let mut out = [0u8; 6];
        let mut parts = s.split([':', '-']);
        for byte in &mut out {
            let part = parts.next().ok_or(())?;
            if part.is_empty() || part.len() > 2 {
                return Err(());
            }
            *byte = u8::from_str_radix(part, 16).map_err(|_| ())?;
        }
        if parts.next().is_some() {
            return Err(());
        }
        Ok(MacAddr(out))
    }
}

/// Which discovery mechanisms have seen a device.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Sources(u8);

impl Sources {
    pub const ARP: Sources = Sources(1);
    pub const MDNS: Sources = Sources(2);
    pub const SSDP: Sources = Sources(4);
    pub const TCP: Sources = Sources(8);

    pub fn insert(&mut self, other: Sources) {
        self.0 |= other.0;
    }

    pub fn contains(&self, other: Sources) -> bool {
        self.0 & other.0 == other.0
    }
}

#[derive(Clone, Default)]
pub struct SsdpInfo {
    pub server: Option<String>,
    pub location: Option<String>,
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
}

#[derive(Clone)]
pub struct Device {
    pub ip: Ipv4Addr,
    pub mac: Option<MacAddr>,
    pub vendor: Option<&'static str>,
    pub alias: Option<String>,
    /// Best human-readable name advertised over mDNS, with its priority.
    mdns_name: Option<(u8, String)>,
    pub mdns_host: Option<String>,
    pub mdns_model: Option<String>,
    /// mDNS service type -> instance name.
    pub services: BTreeMap<String, String>,
    pub ssdp: Option<SsdpInfo>,
    pub ssdp_types: BTreeSet<String>,
    pub rdns: Option<String>,
    pub open_ports: BTreeSet<u16>,
    pub sources: Sources,
    pub is_self: bool,
    pub is_gateway: bool,
    pub first_seen: Instant,
    pub last_seen: Instant,
}

impl Device {
    pub fn new(ip: Ipv4Addr) -> Self {
        let now = Instant::now();
        Device {
            ip,
            mac: None,
            vendor: None,
            alias: None,
            mdns_name: None,
            mdns_host: None,
            mdns_model: None,
            services: BTreeMap::new(),
            ssdp: None,
            ssdp_types: BTreeSet::new(),
            rdns: None,
            open_ports: BTreeSet::new(),
            sources: Sources::default(),
            is_self: false,
            is_gateway: false,
            first_seen: now,
            last_seen: now,
        }
    }

    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }

    pub fn set_mac(&mut self, mac: MacAddr) {
        if self.mac != Some(mac) {
            self.mac = Some(mac);
            self.vendor = oui::lookup(&mac);
        }
    }

    /// The name to show in the device list, best source first.
    pub fn display_name(&self) -> Option<&str> {
        self.alias
            .as_deref()
            .or(self.mdns_name.as_ref().map(|(_, n)| n.as_str()))
            .or(self.ssdp.as_ref().and_then(|s| s.friendly_name.as_deref()))
            .or(self.mdns_host.as_deref())
            .or(self.rdns.as_deref())
            .or(self.mdns_model.as_deref())
            .or(self.ssdp.as_ref().and_then(|s| s.model.as_deref()))
    }

    /// Manufacturer: OUI registry first, then whatever the device says about itself.
    pub fn manufacturer(&self) -> Option<&str> {
        self.vendor.or(self.ssdp.as_ref().and_then(|s| s.manufacturer.as_deref()))
    }

    pub fn model(&self) -> Option<&str> {
        self.mdns_model.as_deref().or(self.ssdp.as_ref().and_then(|s| s.model.as_deref()))
    }

    pub fn apply_mdns(&mut self, rec: &MdnsRecord) {
        self.sources.insert(Sources::MDNS);
        self.touch();
        if let Some(host) = rec.hostname.as_deref().filter(|h| !looks_opaque(h)) {
            self.mdns_host.get_or_insert_with(|| host.to_string());
        }
        if let Some(model) = &rec.model {
            self.mdns_model.get_or_insert_with(|| model.clone());
        }
        if let (Some(service), Some(instance)) = (&rec.service, &rec.instance) {
            self.services.insert(service.clone(), instance.clone());
        }
        let candidate = rec.friendly.as_ref().map(|n| (3, n)).or_else(|| {
            let instance = rec.instance.as_ref()?;
            let service = rec.service.as_deref().unwrap_or_default();
            Some((service_name_priority(service), instance))
        });
        if let Some((prio, name)) = candidate {
            let name = clean_instance_name(name);
            if !name.is_empty() && !looks_opaque(&name) && self.mdns_name.as_ref().is_none_or(|(p, _)| prio > *p) {
                self.mdns_name = Some((prio, name));
            }
        }
    }

    pub fn apply_ssdp(&mut self, rec: &SsdpRecord) {
        self.sources.insert(Sources::SSDP);
        self.touch();
        let info = self.ssdp.get_or_insert_with(Default::default);
        if rec.server.is_some() {
            info.server.clone_from(&rec.server);
        }
        if rec.location.is_some() {
            info.location.clone_from(&rec.location);
        }
        if let Some(st) = &rec.st {
            self.ssdp_types.insert(st.clone());
        }
    }

    pub fn apply_ssdp_description(&mut self, desc: &SsdpDescription) {
        let info = self.ssdp.get_or_insert_with(Default::default);
        let set = |slot: &mut Option<String>, v: &Option<String>| {
            if let Some(v) = v.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
                *slot = Some(v.to_string());
            }
        };
        set(&mut info.friendly_name, &desc.friendly_name);
        set(&mut info.manufacturer, &desc.manufacturer);
        set(&mut info.model, &desc.model);
    }
}

/// How much to trust an instance name from a given service as the device's name.
fn service_name_priority(service: &str) -> u8 {
    match service {
        "_device-info._tcp"
        | "_airplay._tcp"
        | "_companion-link._tcp"
        | "_googlecast._tcp"
        | "_spotify-connect._tcp"
        | "_raop._tcp"
        | "_ipp._tcp"
        | "_ipps._tcp"
        | "_printer._tcp"
        | "_pdl-datastream._tcp"
        | "_uscan._tcp"
        | "_scanner._tcp"
        | "_smb._tcp"
        | "_workstation._tcp"
        | "_sonos._tcp"
        | "_hap._tcp"
        | "_homekit._tcp"
        | "_amzn-wplay._tcp" => 2,
        _ => 1,
    }
}

/// Strip decorations some services add to instance names, e.g. RAOP's
/// `AABBCCDDEEFF@Living Room` or workstation's `host [aa:bb:cc:dd:ee:ff]`.
fn clean_instance_name(name: &str) -> String {
    let mut name = name.trim();
    if let Some((prefix, rest)) = name.split_once('@')
        && prefix.len() == 12
        && prefix.chars().all(|c| c.is_ascii_hexdigit())
    {
        name = rest;
    }
    if let Some(idx) = name.rfind(" [")
        && name.ends_with(']')
    {
        name = &name[..idx];
    }
    name.trim().to_string()
}

/// True for machine-generated identifiers (UUIDs, long hex hashes, MACs)
/// that make poor display names.
pub fn looks_opaque(name: &str) -> bool {
    let core: String = name.chars().filter(|c| !matches!(c, '-' | ':' | '_')).collect();
    let hex = core.chars().all(|c| c.is_ascii_hexdigit());
    (hex && core.len() >= 12) || core.is_empty()
}

/// Human-friendly label for an mDNS service type.
pub fn describe_service(service: &str) -> &str {
    match service {
        "_airplay._tcp" => "AirPlay",
        "_raop._tcp" => "AirPlay audio",
        "_companion-link._tcp" => "Apple companion",
        "_device-info._tcp" => "Device info",
        "_homekit._tcp" | "_hap._tcp" | "_hap._udp" => "HomeKit",
        "_googlecast._tcp" => "Google Cast",
        "_spotify-connect._tcp" => "Spotify Connect",
        "_ipp._tcp" => "IPP printer",
        "_ipps._tcp" => "IPP printer (TLS)",
        "_printer._tcp" => "LPD printer",
        "_pdl-datastream._tcp" => "Raw printing",
        "_uscan._tcp" | "_uscans._tcp" | "_scanner._tcp" => "Scanner",
        "_smb._tcp" => "SMB file sharing",
        "_afpovertcp._tcp" => "AFP file sharing",
        "_ssh._tcp" | "_sftp-ssh._tcp" => "SSH",
        "_http._tcp" => "Web",
        "_https._tcp" => "Web (TLS)",
        "_workstation._tcp" => "Workstation",
        "_sleep-proxy._udp" => "Sleep proxy",
        "_amzn-wplay._tcp" => "Amazon Fire TV",
        "_sonos._tcp" => "Sonos",
        "_matter._tcp" | "_matterc._udp" => "Matter",
        "_meshcop._udp" | "_trel._udp" | "_srpl-tls._tcp" => "Thread border router",
        "_rfb._tcp" => "Screen sharing",
        "_daap._tcp" => "Music sharing",
        "_adisk._tcp" => "Time Machine",
        "_mqtt._tcp" => "MQTT",
        "_esphomelib._tcp" => "ESPHome",
        "_home-assistant._tcp" => "Home Assistant",
        "_philipshue._tcp" | "_hue._tcp" => "Philips Hue",
        _ => service,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mac() {
        let mac: MacAddr = "3c:37:86:18:ee:a3".parse().unwrap();
        assert_eq!(mac.to_string(), "3c:37:86:18:ee:a3");
        let mac: MacAddr = "0:1b:2:3:4:5".parse().unwrap();
        assert_eq!(mac.to_string(), "00:1b:02:03:04:05");
        assert!("3c:37:86:18:ee".parse::<MacAddr>().is_err());
        assert!("3c:37:86:18:ee:a3:00".parse::<MacAddr>().is_err());
        assert!("e2:08:82:3b:b5:97".parse::<MacAddr>().unwrap().is_local());
    }

    #[test]
    fn opaque_names() {
        assert!(looks_opaque("4239E8DA-93AD-4EEF-99DF-6384C0000000"));
        assert!(looks_opaque("921b12e49332d6ff252118bee27b8"));
        assert!(!looks_opaque("Bedroom"));
        assert!(!looks_opaque("cafe"));
    }

    #[test]
    fn instance_cleanup() {
        assert_eq!(clean_instance_name("A1B2C3D4E5F6@Living Room"), "Living Room");
        assert_eq!(clean_instance_name("nas [00:11:22:33:44:55]"), "nas");
        assert_eq!(clean_instance_name("Hope's iPad"), "Hope's iPad");
    }
}
