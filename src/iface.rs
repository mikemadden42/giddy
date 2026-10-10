//! Local IPv4 interface discovery.

use std::net::{Ipv4Addr, UdpSocket};

use crate::device::MacAddr;

/// Never sweep more than this many addresses; larger networks are narrowed
/// to the block around our own address.
pub const MAX_SWEEP_PREFIX: u8 = 22;

#[derive(Clone, Debug)]
pub struct Iface {
    pub name: String,
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub mac: Option<MacAddr>,
    pub gateway: Option<Ipv4Addr>,
}

impl Iface {
    fn mask_for(prefix: u8) -> u32 {
        if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix)) }
    }

    pub fn mask(&self) -> u32 {
        Self::mask_for(self.prefix)
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask() == u32::from(self.ip) & self.mask()
    }

    pub fn cidr(&self) -> String {
        format!("{}/{}", self.ip, self.prefix)
    }

    /// The prefix actually swept (capped at [`MAX_SWEEP_PREFIX`]).
    pub fn sweep_prefix(&self) -> u8 {
        self.prefix.max(MAX_SWEEP_PREFIX)
    }

    /// Host addresses to probe, excluding network, broadcast and ourselves.
    pub fn sweep_targets(&self) -> Vec<Ipv4Addr> {
        let prefix = self.sweep_prefix();
        if prefix >= 31 {
            return Vec::new();
        }
        let mask = Self::mask_for(prefix);
        let net = u32::from(self.ip) & mask;
        let bcast = net | !mask;
        let me = u32::from(self.ip);
        (net + 1..bcast).filter(|a| *a != me).map(Ipv4Addr::from).collect()
    }
}

/// All usable IPv4 interfaces (non-loopback, with a real subnet).
pub fn list() -> Vec<Iface> {
    let Ok(addrs) = if_addrs::get_if_addrs() else { return Vec::new() };
    let mut out: Vec<Iface> = addrs
        .into_iter()
        .filter(|i| !i.is_loopback())
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) => {
                // At most 32, so the conversion can't fail.
                let prefix = u8::try_from(u32::from(v4.netmask).leading_ones()).unwrap_or(32);
                (prefix < 31 && !v4.ip.is_link_local()).then(|| Iface {
                    mac: read_mac(&i.name),
                    gateway: default_gateway(&i.name),
                    name: i.name,
                    ip: v4.ip,
                    prefix,
                })
            }
            if_addrs::IfAddr::V6(_) => None,
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name).then(a.ip.cmp(&b.ip)));
    out.dedup_by(|a, b| a.name == b.name && a.ip == b.ip);
    out
}

/// Index of the interface carrying the default route, found by asking the
/// kernel which source address it would use (no packets are sent).
pub fn default_index(ifaces: &[Iface]) -> Option<usize> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    sock.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).ok()?;
    let local = match sock.local_addr().ok()? {
        std::net::SocketAddr::V4(a) => *a.ip(),
        std::net::SocketAddr::V6(_) => return None,
    };
    ifaces.iter().position(|i| i.ip == local)
}

#[cfg(target_os = "linux")]
fn read_mac(name: &str) -> Option<MacAddr> {
    let text = std::fs::read_to_string(format!("/sys/class/net/{name}/address")).ok()?;
    text.trim().parse().ok().filter(|m: &MacAddr| !m.is_zero())
}

#[cfg(not(target_os = "linux"))]
fn read_mac(_name: &str) -> Option<MacAddr> {
    None
}

#[cfg(target_os = "linux")]
fn default_gateway(name: &str) -> Option<Ipv4Addr> {
    // Columns: Iface Destination Gateway Flags ... (addresses are little-endian hex)
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    text.lines().skip(1).find_map(|line| {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 || cols[0] != name || cols[1] != "00000000" {
            return None;
        }
        let gw = u32::from_str_radix(cols[2], 16).ok()?;
        (gw != 0).then(|| Ipv4Addr::from(gw.swap_bytes()))
    })
}

#[cfg(not(target_os = "linux"))]
fn default_gateway(name: &str) -> Option<Ipv4Addr> {
    // BSD/macOS: `route -n get default` prints "gateway: x.x.x.x" and "interface: en0".
    let out = std::process::Command::new("route").args(["-n", "get", "default"]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let field = |key: &str| text.lines().find_map(|l| l.trim().strip_prefix(key).map(|v| v.trim().to_string()));
    (field("interface:")? == name).then(|| field("gateway:")?.parse().ok()).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(ip: [u8; 4], prefix: u8) -> Iface {
        Iface { name: "test0".into(), ip: ip.into(), prefix, mac: None, gateway: None }
    }

    #[test]
    fn targets_for_slash_24() {
        let i = iface([10, 0, 0, 109], 24);
        let t = i.sweep_targets();
        assert_eq!(t.len(), 253);
        assert_eq!(t[0], Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(*t.last().unwrap(), Ipv4Addr::new(10, 0, 0, 254));
        assert!(!t.contains(&i.ip));
        assert!(i.contains(Ipv4Addr::new(10, 0, 0, 7)));
        assert!(!i.contains(Ipv4Addr::new(10, 0, 1, 7)));
    }

    #[test]
    fn large_networks_are_capped() {
        let i = iface([10, 1, 2, 3], 8);
        assert_eq!(i.sweep_targets().len(), 1021); // /22 minus network, broadcast, self
        assert!(i.sweep_targets().iter().all(|a| a.octets()[1] == 1));
    }
}
