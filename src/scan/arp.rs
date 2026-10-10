//! Reading the kernel's ARP / neighbor cache (no privileges required).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::sync::mpsc::UnboundedSender;

use super::{ScanEvent, Tx};
use crate::device::MacAddr;
use crate::iface::Iface;

#[derive(Debug, PartialEq)]
pub struct Entry {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
    /// Recently confirmed reachable by the kernel. When the platform can't
    /// tell us (e.g. `/proc/net/arp`), every complete entry counts.
    pub active: bool,
}

/// Poll the neighbor table and report entries on `iface`'s subnet.
pub async fn poll(iface: Iface, tx: Tx, rdns: UnboundedSender<Ipv4Addr>) {
    let mut known: HashMap<Ipv4Addr, MacAddr> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tick.tick().await;
        let name = iface.name.clone();
        let Ok(entries) = tokio::task::spawn_blocking(move || read(&name)).await else { continue };
        for e in entries.into_iter().filter(|e| iface.contains(e.ip) && e.ip != iface.ip) {
            let changed = known.insert(e.ip, e.mac) != Some(e.mac);
            if changed {
                let _ = rdns.send(e.ip);
            }
            if changed || e.active {
                let _ = tx.send(ScanEvent::Neighbor { ip: e.ip, mac: e.mac, active: e.active });
            }
        }
    }
}

fn usable(mac: MacAddr) -> bool {
    !mac.is_zero() && !mac.is_broadcast_or_multicast()
}

/// Read neighbor entries for interface `dev`.
pub fn read(dev: &str) -> Vec<Entry> {
    #[cfg(target_os = "linux")]
    {
        // `ip neigh` exposes reachability state; /proc/net/arp is the fallback.
        if let Some(entries) = run("ip", &["-4", "neigh", "show", "dev", dev]).map(|t| parse_ip_neigh(&t)) {
            return entries;
        }
        std::fs::read_to_string("/proc/net/arp").map(|t| parse_proc_arp(&t, dev)).unwrap_or_default()
    }
    #[cfg(windows)]
    {
        let _ = dev;
        run("arp", &["-a"]).map(|t| parse_windows_arp(&t)).unwrap_or_default()
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        run("arp", &["-an"]).map(|t| parse_bsd_arp(&t, dev)).unwrap_or_default()
    }
}

#[cfg_attr(not(any(target_os = "linux", unix, windows)), allow(dead_code))]
fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd).args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `10.0.0.1 lladdr 3c:37:86:00:00:01 router REACHABLE`
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_ip_neigh(text: &str) -> Vec<Entry> {
    text.lines()
        .filter_map(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let ip = tokens.first()?.parse().ok()?;
            let pos = tokens.iter().position(|t| *t == "lladdr")?;
            let mac: MacAddr = tokens.get(pos + 1)?.parse().ok()?;
            let state = *tokens.last()?;
            if matches!(state, "FAILED" | "INCOMPLETE") || !usable(mac) {
                return None;
            }
            let active = matches!(state, "REACHABLE" | "DELAY" | "PROBE");
            Some(Entry { ip, mac, active })
        })
        .collect()
}

/// `IP address  HW type  Flags  HW address  Mask  Device`
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_arp(text: &str, dev: &str) -> Vec<Entry> {
    const ATF_COM: u32 = 0x2;
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let c: Vec<&str> = line.split_whitespace().collect();
            if c.len() < 6 || c[5] != dev {
                return None;
            }
            let flags = u32::from_str_radix(c[2].trim_start_matches("0x"), 16).ok()?;
            let mac: MacAddr = c[3].parse().ok()?;
            let ip = c[0].parse().ok()?;
            (flags & ATF_COM != 0 && usable(mac)).then_some(Entry { ip, mac, active: true })
        })
        .collect()
}

/// `? (10.0.0.1) at 3c:37:86:00:00:01 on en0 ifscope [ethernet]`
#[cfg_attr(any(target_os = "linux", windows), allow(dead_code))]
fn parse_bsd_arp(text: &str, dev: &str) -> Vec<Entry> {
    text.lines()
        .filter_map(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let ip = tokens.get(1)?.trim_matches(['(', ')']).parse().ok()?;
            let at = tokens.iter().position(|t| *t == "at")?;
            let mac: MacAddr = tokens.get(at + 1)?.parse().ok()?;
            let on = tokens.iter().position(|t| *t == "on")?;
            (tokens.get(on + 1) == Some(&dev) && usable(mac)).then_some(Entry { ip, mac, active: true })
        })
        .collect()
}

/// `  10.0.0.1          3c-37-86-18-ee-a3     dynamic`
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_windows_arp(text: &str) -> Vec<Entry> {
    text.lines()
        .filter_map(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let ip = tokens.first()?.parse().ok()?;
            let mac: MacAddr = tokens.get(1)?.parse().ok()?;
            (tokens.get(2) == Some(&"dynamic") && usable(mac)).then_some(Entry { ip, mac, active: true })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_neigh() {
        let text = "10.0.0.1 lladdr 3c:37:86:00:00:01 router REACHABLE\n\
                    10.0.0.5 lladdr 70:f0:88:00:00:03 STALE\n\
                    10.0.0.9  FAILED\n\
                    10.0.0.10 INCOMPLETE\n";
        let e = parse_ip_neigh(text);
        assert_eq!(e.len(), 2);
        assert!(e[0].active && !e[1].active);
        assert_eq!(e[1].mac.to_string(), "70:f0:88:00:00:03");
    }

    #[test]
    fn proc_arp() {
        let text = "IP address       HW type     Flags       HW address            Mask     Device\n\
                    10.0.0.38        0x1         0x2         28:ec:95:00:00:04     *        eth0\n\
                    10.0.0.39        0x1         0x0         00:00:00:00:00:00     *        eth0\n\
                    10.0.0.40        0x1         0x2         28:ec:95:00:00:05     *        wlan0\n";
        let e = parse_proc_arp(text, "eth0");
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].ip, Ipv4Addr::new(10, 0, 0, 38));
    }

    #[test]
    fn bsd_and_windows_arp() {
        let bsd = "? (10.0.0.1) at 3c:37:86:00:00:01 on en0 ifscope [ethernet]\n\
                   ? (10.0.0.2) at (incomplete) on en0 ifscope [ethernet]\n\
                   ? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]\n";
        assert_eq!(parse_bsd_arp(bsd, "en0").len(), 1);
        let win = "Interface: 10.0.0.5 --- 0x7\n  Internet Address      Physical Address      Type\n  \
                   10.0.0.1              3c-37-86-18-ee-a3     dynamic\n  \
                   10.0.0.255            ff-ff-ff-ff-ff-ff     static\n";
        assert_eq!(parse_windows_arp(win).len(), 1);
    }
}
