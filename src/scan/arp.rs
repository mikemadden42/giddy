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
        let ip = iface.ip;
        let Ok(entries) = tokio::task::spawn_blocking(move || read(&name, ip)).await else { continue };
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

/// Read neighbor entries for interface `dev` and local IPv4 address `ip`.
pub fn read(dev: &str, ip: Ipv4Addr) -> Vec<Entry> {
    read_result(dev, ip).unwrap_or_default()
}

/// Read neighbor entries while preserving failures separately from an empty table.
pub fn read_result(dev: &str, ip: Ipv4Addr) -> std::io::Result<Vec<Entry>> {
    #[cfg(not(windows))]
    let _ = ip;
    #[cfg(target_os = "linux")]
    {
        // `ip neigh` exposes reachability state; /proc/net/arp is the fallback.
        if let Ok(text) = run("ip", &["-4", "neigh", "show", "dev", dev]) {
            return Ok(parse_ip_neigh(&text));
        }
        let text = std::fs::read_to_string("/proc/net/arp")?;
        Ok(parse_proc_arp(&text, dev))
    }
    #[cfg(windows)]
    {
        let _ = dev;
        run("arp", &["-a"]).map(|text| parse_windows_arp(&text, ip))
    }
    // macOS hides the table from an `arp` we spawn, so ask the kernel directly.
    #[cfg(target_os = "macos")]
    {
        sysctl_arp(dev)
    }
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    {
        run("arp", &["-an"]).map(|text| parse_bsd_arp(&text, dev))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows, unix)))]
    {
        let _ = (dev, ip);
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "neighbor table reading is unsupported"))
    }
}

/// What `arp -an` does: fetch the `RTF_LLINFO` routes via `sysctl(NET_RT_FLAGS)`.
#[cfg(target_os = "macos")]
fn sysctl_arp(dev: &str) -> std::io::Result<Vec<Entry>> {
    let name = std::ffi::CString::new(dev)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "interface name contains NUL"))?;
    // SAFETY: `name` is NUL-terminated.
    let raw_index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    // 0 means no such interface; route messages carry the index as a u16.
    let index = u16::try_from(raw_index)
        .ok()
        .filter(|index| *index != 0)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "interface not found"))?;
    let mut mib = [libc::CTL_NET, libc::PF_ROUTE, 0, libc::AF_INET, libc::NET_RT_FLAGS, libc::RTF_LLINFO];
    let null = std::ptr::null_mut();
    let mut len = 0;
    // SAFETY: a null buffer asks only for the required size.
    if unsafe { libc::sysctl(mib.as_mut_ptr(), 6, null, &raw mut len, null, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Headroom in case the table grows between the two calls.
    let mut buf = vec![0u8; len * 2];
    len = buf.len();
    // SAFETY: `buf` is writable for `len` bytes.
    if unsafe { libc::sysctl(mib.as_mut_ptr(), 6, buf.as_mut_ptr().cast(), &raw mut len, null, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(len);
    Ok(parse_rt_msgs(&buf, index))
}

/// Walk `rt_msghdr` records on interface `if_index`. Each header is followed
/// by `RTA_DST` (a `sockaddr_in`) then `RTA_GATEWAY` (a `sockaddr_dl` with the MAC).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_rt_msgs(mut buf: &[u8], if_index: u16) -> Vec<Entry> {
    const HDR_LEN: usize = 92; // size_of::<rt_msghdr>() on Darwin
    let mut entries = Vec::new();
    while buf.len() >= HDR_LEN {
        let msglen = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
        if msglen < HDR_LEN || msglen > buf.len() {
            break;
        }
        let (msg, rest) = buf.split_at(msglen);
        buf = rest;
        if u16::from_ne_bytes([msg[4], msg[5]]) != if_index {
            continue;
        }
        let dst = &msg[HDR_LEN..];
        // sockaddr_in: len, family (AF_INET = 2), port, addr. Padded to 4 bytes.
        if dst.len() < 8 || dst[1] != 2 {
            continue;
        }
        let ip = Ipv4Addr::new(dst[4], dst[5], dst[6], dst[7]);
        let gw = &dst[(dst[0] as usize).next_multiple_of(4)..];
        // sockaddr_dl: len, family (AF_LINK = 18), index, type, nlen, alen, slen, data.
        if gw.len() < 8 || gw[1] != 18 || gw[6] != 6 {
            continue;
        }
        let start = 8 + gw[5] as usize;
        let Some(mac) = gw.get(start..start + 6) else { continue };
        let mac = MacAddr(mac.try_into().unwrap());
        if usable(mac) {
            entries.push(Entry { ip, mac, active: true });
        }
    }
    entries
}
#[cfg_attr(target_os = "macos", allow(dead_code))]
#[cfg_attr(not(any(target_os = "linux", unix, windows)), allow(dead_code))]
fn run(cmd: &str, args: &[&str]) -> std::io::Result<String> {
    let out = std::process::Command::new(cmd).args(args).output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!("{cmd} exited with {}", out.status)));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
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
#[cfg_attr(any(target_os = "linux", target_os = "macos", windows), allow(dead_code))]
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

/// `  10.0.0.1          3c-37-86-00-00-01     dynamic`
///
/// Windows localizes the type column, so identify complete neighbor rows by
/// their address fields instead of matching the English word `dynamic`.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_windows_arp(text: &str, selected_ip: Ipv4Addr) -> Vec<Entry> {
    let mut selected_section = false;
    text.lines()
        .filter_map(|line| {
            // Windows prints one section per interface address. The label may
            // be localized, but the separator and IPv4 address are stable.
            if let Some((header, _)) = line.split_once("---") {
                selected_section = header
                    .split_whitespace()
                    .filter_map(|token| token.parse::<Ipv4Addr>().ok())
                    .any(|ip| ip == selected_ip);
                return None;
            }
            if !selected_section {
                return None;
            }
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let ip = tokens.first()?.parse().ok()?;
            let mac: MacAddr = tokens.get(1)?.parse().ok()?;
            usable(mac).then_some(Entry { ip, mac, active: true })
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
    fn rt_msgs() {
        fn msg(index: u16, ip: [u8; 4], mac: Option<[u8; 6]>) -> Vec<u8> {
            let mut m = vec![0u8; 92];
            m[4..6].copy_from_slice(&index.to_ne_bytes());
            m.extend([16, 2, 0, 0]);
            m.extend(ip);
            m.extend([0; 8]);
            // An incomplete entry has a sockaddr_dl with no address.
            m.extend([20, 18, 0, 0, 6, 0, if mac.is_some() { 6 } else { 0 }, 0]);
            m.extend(mac.unwrap_or_default());
            m.extend([0; 6]);
            let len = u16::try_from(m.len()).unwrap();
            m[0..2].copy_from_slice(&len.to_ne_bytes());
            m
        }
        let buf = [
            msg(4, [10, 0, 0, 1], Some([0x3c, 0x37, 0x86, 0x00, 0x00, 0x01])),
            msg(4, [10, 0, 0, 2], None),
            msg(7, [10, 0, 0, 3], Some([0x3c, 0x37, 0x86, 0x00, 0x00, 0x02])),
            msg(4, [10, 0, 0, 255], Some([0xff; 6])),
        ]
        .concat();
        let e = parse_rt_msgs(&buf, 4);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(e[0].mac.to_string(), "3c:37:86:00:00:01");
    }

    #[test]
    fn bsd_and_windows_arp() {
        let bsd = "? (10.0.0.1) at 3c:37:86:00:00:01 on en0 ifscope [ethernet]\n\
                   ? (10.0.0.2) at (incomplete) on en0 ifscope [ethernet]\n\
                   ? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]\n";
        assert_eq!(parse_bsd_arp(bsd, "en0").len(), 1);
        let win = "Interface: 10.0.0.5 --- 0x7\n  Internet Address      Physical Address      Type\n  \
                   10.0.0.1              3c-37-86-00-00-01     dynamic\n  \
                   10.0.0.255            ff-ff-ff-ff-ff-ff     static\n";
        assert_eq!(parse_windows_arp(win, Ipv4Addr::new(10, 0, 0, 5)).len(), 1);
    }
}
