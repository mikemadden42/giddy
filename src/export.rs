//! Machine- and human-readable output for `--once`.

use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::ValueEnum;
use serde::Serialize;

use crate::device::{Device, describe_service};
use crate::iface::Iface;
use crate::kind;

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum Format {
    /// Aligned columns for reading in a terminal
    #[default]
    Table,
    /// A JSON document with every detail giddy collected
    Json,
    /// One row per device, RFC 4180 quoting
    Csv,
}

pub fn write(out: &mut impl Write, format: Format, iface: &Iface, devices: &[&Device]) -> io::Result<()> {
    match format {
        Format::Table => table(out, devices),
        Format::Json => json(out, iface, devices),
        Format::Csv => csv(out, devices),
    }
}

fn table(out: &mut impl Write, devices: &[&Device]) -> io::Result<()> {
    writeln!(out, "{:<15}  {:<10}  {:<32}  {:<17}  MANUFACTURER", "IP", "TYPE", "NAME", "MAC")?;
    for d in devices {
        let name: String = d.display_name().unwrap_or("-").chars().take(32).collect();
        let mac = d.mac.map_or_else(|| "-".into(), |m| m.to_string());
        let vendor = d.manufacturer().unwrap_or(if d.mac.is_some_and(|m| m.is_local()) { "(private)" } else { "" });
        let kind = kind::classify(d).map_or("-", kind::Kind::label);
        writeln!(out, "{:<15}  {:<10}  {:<32}  {:<17}  {}", d.ip, kind, name, mac, vendor)?;
    }
    Ok(())
}

#[derive(Serialize)]
struct Report<'a> {
    giddy_version: &'static str,
    /// Unix time (seconds) when the report was written.
    scanned_at: u64,
    interface: &'a str,
    network: String,
    devices: Vec<DeviceJson<'a>>,
}

/// Every key is always present (`null` or `[]` when unknown) so consumers
/// can rely on a fixed shape.
#[derive(Serialize)]
struct DeviceJson<'a> {
    ip: String,
    mac: Option<String>,
    randomized_mac: bool,
    name: Option<&'a str>,
    alias: Option<&'a str>,
    #[serde(rename = "type")]
    kind: Option<&'static str>,
    manufacturer: Option<&'a str>,
    model: Option<&'a str>,
    mdns_host: Option<&'a str>,
    dns_name: Option<&'a str>,
    netbios_name: Option<&'a str>,
    workgroup: Option<&'a str>,
    gateway: bool,
    this_device: bool,
    open_ports: Vec<u16>,
    seen_via: Vec<&'static str>,
    services: Vec<ServiceJson<'a>>,
    upnp: Option<UpnpJson<'a>>,
    web: Option<WebJson<'a>>,
    ssh: Option<&'a str>,
}

#[derive(Serialize)]
struct ServiceJson<'a> {
    #[serde(rename = "type")]
    service: &'a str,
    label: &'a str,
    instance: &'a str,
}

#[derive(Serialize)]
struct UpnpJson<'a> {
    friendly_name: Option<&'a str>,
    manufacturer: Option<&'a str>,
    model: Option<&'a str>,
    server: Option<&'a str>,
    location: Option<&'a str>,
    device_types: Vec<&'a str>,
}

#[derive(Serialize)]
struct WebJson<'a> {
    server: Option<&'a str>,
    realm: Option<&'a str>,
    title: Option<&'a str>,
}

impl<'a> DeviceJson<'a> {
    fn new(d: &'a Device) -> Self {
        DeviceJson {
            ip: d.ip.to_string(),
            mac: d.mac.map(|m| m.to_string()),
            randomized_mac: d.mac.is_some_and(|m| m.is_local()),
            name: d.display_name(),
            alias: d.alias.as_deref(),
            kind: kind::classify(d).map(kind::Kind::label),
            manufacturer: d.manufacturer(),
            model: d.model(),
            mdns_host: d.mdns_host.as_deref(),
            dns_name: d.rdns.as_deref(),
            netbios_name: d.netbios_name.as_deref(),
            workgroup: d.workgroup.as_deref(),
            gateway: d.is_gateway,
            this_device: d.is_self,
            open_ports: d.open_ports.iter().copied().collect(),
            seen_via: d.sources.names(),
            services: d
                .services
                .iter()
                .map(|(service, instance)| ServiceJson { service, label: describe_service(service), instance })
                .collect(),
            upnp: d.ssdp.as_ref().map(|s| UpnpJson {
                friendly_name: s.friendly_name.as_deref(),
                manufacturer: s.manufacturer.as_deref(),
                model: s.model.as_deref(),
                server: s.server.as_deref(),
                location: s.location.as_deref(),
                device_types: d.ssdp_types.iter().map(String::as_str).collect(),
            }),
            web: d.http.as_ref().map(|h| WebJson {
                server: h.server.as_deref(),
                realm: h.realm.as_deref(),
                title: h.title.as_deref(),
            }),
            ssh: d.ssh_banner.as_deref(),
        }
    }
}

fn json(out: &mut impl Write, iface: &Iface, devices: &[&Device]) -> io::Result<()> {
    let report = Report {
        giddy_version: env!("CARGO_PKG_VERSION"),
        scanned_at: SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()),
        interface: &iface.name,
        network: iface.cidr(),
        devices: devices.iter().map(|d| DeviceJson::new(d)).collect(),
    };
    serde_json::to_writer_pretty(&mut *out, &report)?;
    writeln!(out)
}

const CSV_HEADER: &[&str] = &[
    "ip",
    "type",
    "name",
    "mac",
    "randomized_mac",
    "manufacturer",
    "model",
    "mdns_host",
    "dns_name",
    "netbios_name",
    "open_ports",
    "seen_via",
    "gateway",
    "this_device",
];

fn csv(out: &mut impl Write, devices: &[&Device]) -> io::Result<()> {
    write_csv_row(out, CSV_HEADER.iter().map(|s| s.to_string()))?;
    for d in devices {
        let ports: Vec<String> = d.open_ports.iter().map(u16::to_string).collect();
        let text = |s: Option<&str>| s.unwrap_or_default().to_string();
        write_csv_row(
            out,
            [
                d.ip.to_string(),
                text(kind::classify(d).map(kind::Kind::label)),
                text(d.display_name()),
                d.mac.map(|m| m.to_string()).unwrap_or_default(),
                d.mac.is_some_and(|m| m.is_local()).to_string(),
                text(d.manufacturer()),
                text(d.model()),
                text(d.mdns_host.as_deref()),
                text(d.rdns.as_deref()),
                text(d.netbios_name.as_deref()),
                ports.join(";"),
                d.sources.names().join(";"),
                d.is_gateway.to_string(),
                d.is_self.to_string(),
            ]
            .into_iter(),
        )?;
    }
    Ok(())
}

fn write_csv_row(out: &mut impl Write, fields: impl Iterator<Item = String>) -> io::Result<()> {
    let row: Vec<String> = fields.map(|f| csv_field(&f)).collect();
    // RFC 4180 specifies CRLF line endings.
    write!(out, "{}\r\n", row.join(","))
}

/// Quote a field if it contains a comma, quote or line break; double inner quotes.
fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{MacAddr, Sources};

    fn sample() -> (Iface, Device) {
        let iface = Iface { name: "eth0".into(), ip: [10, 0, 0, 2].into(), prefix: 24, mac: None, gateway: None };
        let mut d = Device::new([10, 0, 0, 72].into());
        d.set_mac(MacAddr([0x94, 0xdd, 0xf8, 0xf4, 0x80, 0xce]));
        d.rdns = Some("printer, \"office\"".into());
        d.open_ports.extend([80, 443]);
        d.sources.insert(Sources::ARP);
        d.sources.insert(Sources::TCP);
        d.services.insert("_ipp._tcp".into(), "Brother".into());
        (iface, d)
    }

    #[test]
    fn csv_quotes_and_joins() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");

        let (_, d) = sample();
        let mut out = Vec::new();
        csv(&mut out, &[&d]).unwrap();
        let text = String::from_utf8(out).unwrap();
        let mut lines = text.split("\r\n");
        assert!(lines.next().unwrap().starts_with("ip,type,name,mac,"));
        let row = lines.next().unwrap();
        assert!(row.starts_with(
            "10.0.0.72,printer,\"printer, \"\"office\"\"\",94:dd:f8:f4:80:ce,false,\"Brother Industries, LTD.\","
        ));
        assert!(row.contains(",80;443,arp;tcp,false,false"));
    }

    #[test]
    fn json_has_a_stable_shape() {
        let (iface, d) = sample();
        let mut out = Vec::new();
        json(&mut out, &iface, &[&d]).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["network"], "10.0.0.2/24");
        let dev = &v["devices"][0];
        assert_eq!(dev["ip"], "10.0.0.72");
        assert_eq!(dev["type"], "printer");
        assert_eq!(dev["manufacturer"], "Brother Industries, LTD.");
        assert_eq!(dev["open_ports"], serde_json::json!([80, 443]));
        assert_eq!(dev["seen_via"], serde_json::json!(["arp", "tcp"]));
        assert_eq!(dev["services"][0]["label"], "IPP printer");
        assert!(dev["upnp"].is_null() && dev["ssh"].is_null());
    }
}
