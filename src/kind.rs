//! Best-guess device type from what discovery already collected: no extra
//! network traffic. Rules run from most to least specific; the first
//! confident match wins.

use crate::device::{Device, Sources};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Router,
    Network,
    Computer,
    Phone,
    Tablet,
    /// An iOS device we can't tell apart (phone or tablet).
    Mobile,
    Tv,
    Speaker,
    Console,
    Printer,
    Camera,
    Storage,
    SmartHome,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Router => "router",
            Kind::Network => "network",
            Kind::Computer => "computer",
            Kind::Phone => "phone",
            Kind::Tablet => "tablet",
            Kind::Mobile => "mobile",
            Kind::Tv => "tv",
            Kind::Speaker => "speaker",
            Kind::Console => "console",
            Kind::Printer => "printer",
            Kind::Camera => "camera",
            Kind::Storage => "storage",
            Kind::SmartHome => "smart home",
        }
    }
}

pub fn classify(d: &Device) -> Option<Kind> {
    if d.is_self {
        return Some(Kind::Computer);
    }
    if d.is_gateway {
        return Some(Kind::Router);
    }
    from_apple_model(d)
        .or_else(|| from_services(d))
        .or_else(|| from_upnp(d))
        .or_else(|| from_names(d))
        .or_else(|| from_ports(d))
        .or_else(|| from_vendor(d))
}

/// Apple publishes hardware identifiers like `iPhone14,2` or `AppleTV11,1`
/// in mDNS TXT records.
fn from_apple_model(d: &Device) -> Option<Kind> {
    let model = d.mdns_model.as_deref()?;
    let table: &[(&str, Kind)] = &[
        ("iPhone", Kind::Phone),
        ("iPad", Kind::Tablet),
        ("iPod", Kind::Mobile),
        ("AppleTV", Kind::Tv),
        ("AudioAccessory", Kind::Speaker), // HomePod
        ("Mac", Kind::Computer),           // Mac, MacBook*, Macmini, MacPro
        ("iMac", Kind::Computer),
        ("AirPort", Kind::Network),
    ];
    table.iter().find(|(prefix, _)| model.starts_with(prefix)).map(|(_, k)| *k)
}

fn from_services(d: &Device) -> Option<Kind> {
    let has = |s: &str| d.services.contains_key(s);
    let vendor = d.manufacturer().unwrap_or_default().to_lowercase();
    if ["_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp"].iter().any(|s| has(s)) {
        return Some(Kind::Printer);
    }
    if has("_googlecast._tcp") {
        // Google Home/Nest speakers cast too; their TXT model says so.
        let model = d.model().unwrap_or_default().to_lowercase();
        let speaker = ["home", "nest audio", "nest mini", "speaker"].iter().any(|w| model.contains(w));
        return Some(if speaker && !model.contains("hub") { Kind::Speaker } else { Kind::Tv });
    }
    if has("_sonos._tcp") {
        return Some(Kind::Speaker);
    }
    if has("_amzn-wplay._tcp") {
        return Some(Kind::Tv); // Fire TV
    }
    if has("_spotify-connect._tcp") && vendor.contains("amazon") {
        return Some(Kind::Speaker); // Echo
    }
    if has("_home-assistant._tcp") {
        return Some(Kind::Computer);
    }
    if ["_hap._tcp", "_hap._udp", "_homekit._tcp", "_matter._tcp", "_esphomelib._tcp", "_hue._tcp"]
        .iter()
        .any(|s| has(s))
    {
        return Some(Kind::SmartHome);
    }
    if has("_adisk._tcp") || ((has("_smb._tcp") || has("_afpovertcp._tcp")) && is_nas_vendor(&vendor)) {
        return Some(Kind::Storage);
    }
    if has("_workstation._tcp") || has("_ssh._tcp") || has("_rfb._tcp") {
        return Some(Kind::Computer);
    }
    None
}

fn from_upnp(d: &Device) -> Option<Kind> {
    let types: Vec<String> = d.ssdp_types.iter().map(|t| t.to_lowercase()).collect();
    let any = |needle: &str| types.iter().any(|t| t.contains(needle));
    if any("internetgatewaydevice") || any("wanconnectiondevice") {
        return Some(Kind::Router);
    }
    if any("roku:ecp") || any("dial-multiscreen") {
        return Some(Kind::Tv);
    }
    if any("zoneplayer") {
        return Some(Kind::Speaker); // Sonos
    }
    if any("printer") {
        return Some(Kind::Printer);
    }
    if any("digitalsecuritycamera") || any("networkvideotransmitter") {
        return Some(Kind::Camera);
    }
    if any("mediarenderer") {
        return Some(Kind::Tv);
    }
    if any("mediaserver") {
        return Some(Kind::Storage);
    }
    None
}

/// Keywords in anything the device calls itself.
fn from_names(d: &Device) -> Option<Kind> {
    let mut text = String::new();
    for s in [
        d.display_name(),
        d.mdns_host.as_deref(),
        d.netbios_name.as_deref(),
        d.rdns.as_deref(),
        d.web_label(),
        d.model(),
        d.ssdp.as_ref().and_then(|s| s.friendly_name.as_deref()),
    ]
    .into_iter()
    .flatten()
    {
        text.push(' ');
        text.push_str(&s.to_lowercase());
    }
    let words: Vec<&str> = text.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).collect();
    // Short keywords must be whole words; longer ones may be part of one
    // (e.g. "iphone" in "guest-iphone").
    let matches = |kw: &str| if kw.len() <= 4 { words.contains(&kw) } else { text.contains(kw) };
    let table: &[(&[&str], Kind)] = &[
        (&["iphone", "android", "galaxy", "pixel"], Kind::Phone),
        (&["ipad", "tablet", "kindle"], Kind::Tablet),
        (&["orbi", "satellite", "extender", "access point", "eero", "mesh", "repeater"], Kind::Network),
        (&["router", "gateway"], Kind::Router),
        (&["macbook", "imac", "mac mini", "macmini", "laptop", "desktop", "thinkpad", "pc"], Kind::Computer),
        (&["printer", "laserjet", "officejet", "deskjet", "pixma"], Kind::Printer),
        (&["apple tv", "appletv", "roku", "chromecast", "fire tv", "firetv", "shield", "tv"], Kind::Tv),
        (&["homepod", "echo", "sonos", "speaker", "soundbar"], Kind::Speaker),
        (&["xbox", "playstation", "ps4", "ps5", "nintendo"], Kind::Console),
        (&["camera", "doorbell", "cam", "ipcam"], Kind::Camera),
        (&["diskstation", "synology", "qnap", "nas"], Kind::Storage),
        (&["thermostat", "plug", "bulb", "hue", "lamp"], Kind::SmartHome),
    ];
    table.iter().find(|(kws, _)| kws.iter().any(|k| matches(k))).map(|(_, k)| *k)
}

fn from_ports(d: &Device) -> Option<Kind> {
    if d.open_ports.contains(&62078) {
        return Some(Kind::Mobile); // iOS lockdownd (iTunes Wi-Fi sync)
    }
    if let Some(ssh) = &d.ssh_banner {
        let ssh = ssh.to_lowercase();
        if ["ubuntu", "debian", "raspbian", "fedora", "freebsd"].iter().any(|os| ssh.contains(os)) {
            return Some(Kind::Computer);
        }
    }
    if d.sources.contains(Sources::NETBIOS) || d.open_ports.contains(&445) {
        return Some(Kind::Computer); // Windows, Samba or macOS file sharing
    }
    None
}

/// Manufacturers that make essentially one kind of device. Brands with
/// broad lineups (Apple, Amazon, Google, Samsung…) are left out.
fn from_vendor(d: &Device) -> Option<Kind> {
    let vendor = d.manufacturer()?.to_lowercase();
    if is_nas_vendor(&vendor) {
        return Some(Kind::Storage);
    }
    let table: &[(&[&str], Kind)] = &[
        (&["nintendo", "sony interactive"], Kind::Console),
        (&["brother", "canon", "seiko epson", "lexmark", "kyocera", "xerox", "ricoh"], Kind::Printer),
        (&["sonos", "bose"], Kind::Speaker),
        (&["roku"], Kind::Tv),
        (&["ring llc", "arlo", "wyze", "hikvision", "dahua", "axis communications", "reolink"], Kind::Camera),
        (&["espressif", "tuya", "shelly", "signify", "philips lighting", "ecobee", "nest labs"], Kind::SmartHome),
        (&["raspberry pi", "dell", "lenovo", "micro-star", "asustek", "giga-byte", "intel corporate"], Kind::Computer),
        (&["netgear", "ubiquiti", "eero", "aruba", "cisco", "juniper", "mikrotik"], Kind::Network),
    ];
    table.iter().find(|(names, _)| names.iter().any(|n| vendor.contains(n))).map(|(_, k)| *k)
}

fn is_nas_vendor(vendor: &str) -> bool {
    ["synology", "qnap", "western digital", "asustor", "drobo"].iter().any(|n| vendor.contains(n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MacAddr;

    fn device() -> Device {
        Device::new([10, 0, 0, 9].into())
    }

    #[test]
    fn apple_models() {
        let mut d = device();
        d.mdns_model = Some("AppleTV11,1".into());
        assert_eq!(classify(&d), Some(Kind::Tv));
        d.mdns_model = Some("MacBookPro18,3".into());
        assert_eq!(classify(&d), Some(Kind::Computer));
        d.mdns_model = Some("AudioAccessory5,1".into());
        assert_eq!(classify(&d), Some(Kind::Speaker));
    }

    #[test]
    fn services_beat_names() {
        let mut d = device();
        d.rdns = Some("office-tv".into());
        d.services.insert("_ipp._tcp".into(), "Brother".into());
        assert_eq!(classify(&d), Some(Kind::Printer));
    }

    #[test]
    fn name_keywords() {
        let mut d = device();
        d.mdns_host = Some("Guest-iPhone".into());
        assert_eq!(classify(&d), Some(Kind::Phone));
        d.mdns_host = Some("Kitchen-iPad".into());
        assert_eq!(classify(&d), Some(Kind::Tablet));
        // "tv" must be a whole word, not part of "tvheadend"-style names.
        d.mdns_host = Some("tvheadend".into());
        assert_eq!(classify(&d), None);
        d.mdns_host = Some("living-room-tv".into());
        assert_eq!(classify(&d), Some(Kind::Tv));
    }

    #[test]
    fn web_realm_names_mesh_nodes() {
        let mut d = device();
        d.http = Some(crate::scan::HttpInfo { realm: Some("NETGEAR Orbi-micro".into()), ..Default::default() });
        assert_eq!(classify(&d), Some(Kind::Network));
    }

    #[test]
    fn ports_and_vendor_fallbacks() {
        let mut d = device();
        d.set_mac(MacAddr([0x4e, 0x9e, 0x78, 0x00, 0x00, 0x07])); // randomized
        assert_eq!(classify(&d), None);
        d.open_ports.insert(62078);
        assert_eq!(classify(&d), Some(Kind::Mobile));

        let mut d = device();
        d.set_mac(MacAddr([0x70, 0xf0, 0x88, 0x00, 0x00, 0x03])); // Nintendo
        assert_eq!(classify(&d), Some(Kind::Console));

        // An Apple device answering NetBIOS is a Mac with file sharing on.
        let mut d = device();
        d.set_mac(MacAddr([0x50, 0xa6, 0xd8, 0x00, 0x00, 0x08]));
        assert_eq!(classify(&d), None);
        d.sources.insert(Sources::NETBIOS);
        assert_eq!(classify(&d), Some(Kind::Computer));
    }

    #[test]
    fn amazon_spotify_is_an_echo() {
        let mut d = device();
        d.set_mac(MacAddr([0x08, 0x7c, 0x39, 0x00, 0x00, 0x09])); // Amazon
        assert_eq!(classify(&d), None);
        d.services.insert("_spotify-connect._tcp".into(), "SpotifyConnect".into());
        assert_eq!(classify(&d), Some(Kind::Speaker));
    }
}
