//! NetBIOS node status queries (RFC 1002 NBSTAT). A unicast datagram to
//! UDP 137 asks a host for its NetBIOS name table; Windows machines, Samba
//! servers and most NAS boxes answer with their hostname, workgroup and MAC.
//! Sent from an ephemeral port, so no privileges are needed.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use tokio::net::UdpSocket;

use super::{NetBiosRecord, ScanEvent, Tx, recv_for};
use crate::device::MacAddr;
use crate::iface::Iface;

const PORT: u16 = 137;
const TYPE_NBSTAT: u16 = 0x21;
/// Name-table entry flag marking a group (shared) name rather than a host's own.
const GROUP_FLAG: u16 = 0x8000;
/// Name suffixes: 0x00 is the workstation service, 0x20 the file server.
const SUFFIX_WORKSTATION: u8 = 0x00;
const SUFFIX_SERVER: u8 = 0x20;

/// Query the hosts in the ARP cache (run after the sweep has filled it),
/// then collect replies. Only resolved hosts are asked: datagrams to empty
/// addresses would sit in the socket buffer awaiting ARP and stall sends.
pub async fn query(iface: &Iface, tx: &Tx) -> anyhow::Result<()> {
    let dev = iface.name.clone();
    let neighbors = tokio::task::spawn_blocking(move || super::arp::read(&dev)).await?;
    let targets: Vec<Ipv4Addr> = neighbors.into_iter().map(|e| e.ip).filter(|ip| iface.contains(*ip)).collect();
    let sock = UdpSocket::bind(SocketAddrV4::new(iface.ip, 0)).await?;
    let request = build_request(0x6764);

    // A second pass covers lost datagrams; it's UDP.
    for window in [1200, 1200] {
        for ip in &targets {
            let _ = sock.send_to(&request, SocketAddrV4::new(*ip, PORT)).await;
        }
        recv_for(&sock, Duration::from_millis(window), |buf, src| {
            if iface.contains(src)
                && let Some(rec) = parse_response(buf, src)
            {
                let _ = tx.send(ScanEvent::NetBios(rec));
            }
        })
        .await;
    }
    Ok(())
}

/// A node status request for the wildcard name `*`.
fn build_request(id: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(50);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]); // flags, qd=1, an/ns/ar=0
    buf.extend_from_slice(&encode_name(b"*"));
    buf.extend_from_slice(&TYPE_NBSTAT.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // class IN
    buf
}

/// NetBIOS "first-level" encoding: pad to 16 bytes with NULs, then split
/// each byte into two nibbles written as 'A' + nibble.
fn encode_name(name: &[u8]) -> Vec<u8> {
    let mut padded = [0u8; 16];
    padded[..name.len()].copy_from_slice(name);
    let mut out = Vec::with_capacity(34);
    out.push(32);
    for b in padded {
        out.push(b'A' + (b >> 4));
        out.push(b'A' + (b & 0x0f));
    }
    out.push(0);
    out
}

fn parse_response(buf: &[u8], ip: Ipv4Addr) -> Option<NetBiosRecord> {
    let flags = u16::from_be_bytes([*buf.get(2)?, *buf.get(3)?]);
    let answers = u16::from_be_bytes([*buf.get(6)?, *buf.get(7)?]);
    if flags & 0x8000 == 0 || answers == 0 {
        return None;
    }
    // Skip the answer's name: either a pointer or length-prefixed labels.
    let mut pos = 12;
    loop {
        let len = *buf.get(pos)? as usize;
        if len & 0xc0 == 0xc0 {
            pos += 2;
            break;
        }
        pos += 1 + len;
        if len == 0 {
            break;
        }
    }
    let rtype = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]);
    if rtype != TYPE_NBSTAT {
        return None;
    }
    pos += 10; // type, class, ttl, rdlength
    let count = *buf.get(pos)? as usize;
    pos += 1;

    let mut name = None;
    let mut server_name = None;
    let mut group = None;
    for _ in 0..count {
        let entry = buf.get(pos..pos + 18)?;
        pos += 18;
        let raw = decode_name(&entry[..15]);
        let suffix = entry[15];
        let is_group = u16::from_be_bytes([entry[16], entry[17]]) & GROUP_FLAG != 0;
        if raw.is_empty() {
            continue;
        }
        match (suffix, is_group) {
            (SUFFIX_WORKSTATION, false) => name = name.or(Some(raw)),
            (SUFFIX_SERVER, false) => server_name = server_name.or(Some(raw)),
            (SUFFIX_WORKSTATION, true) => group = group.or(Some(raw)),
            _ => {}
        }
    }
    // The statistics block starts with the adapter's MAC ("unit ID"). Samba
    // reports zeros, so only keep a real address.
    let mac = buf
        .get(pos..pos + 6)
        .map(|b| MacAddr([b[0], b[1], b[2], b[3], b[4], b[5]]))
        .filter(|m| !m.is_zero() && !m.is_broadcast_or_multicast());

    Some(NetBiosRecord { ip, name: name.or(server_name), group, mac })
}

/// Names are space-padded OEM text.
fn decode_name(raw: &[u8]) -> String {
    let text: String = raw.iter().map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { ' ' }).collect();
    text.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_encodes_wildcard() {
        let req = build_request(1);
        assert_eq!(req.len(), 50);
        assert_eq!(&req[12..15], &[32, b'C', b'K']); // '*' = 0x2A
        assert_eq!(req[15], b'A'); // NUL padding
        assert_eq!(&req[46..50], &[0, 0x21, 0, 1]);
    }

    fn entry(name: &str, suffix: u8, flags: u16) -> Vec<u8> {
        let mut e = format!("{name:<15}").into_bytes();
        e.push(suffix);
        e.extend_from_slice(&flags.to_be_bytes());
        e
    }

    fn response(entries: &[Vec<u8>], mac: [u8; 6]) -> Vec<u8> {
        let mut b = vec![0x67, 0x64, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0];
        b.extend_from_slice(&encode_name(b"*"));
        b.extend_from_slice(&[0, 0x21, 0, 1, 0, 0, 0, 0]);
        let mut rdata = vec![u8::try_from(entries.len()).unwrap()];
        for e in entries {
            rdata.extend_from_slice(e);
        }
        rdata.extend_from_slice(&mac);
        rdata.extend_from_slice(&[0; 40]); // remaining statistics
        b.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
        b.extend_from_slice(&rdata);
        b
    }

    #[test]
    fn parses_windows_name_table() {
        let buf = response(
            &[
                entry("DESKTOP-7Q2LM", 0x00, 0x0400),
                entry("WORKGROUP", 0x00, 0x8400),
                entry("DESKTOP-7Q2LM", 0x20, 0x0400),
                entry("\u{1}\u{2}__MSBROWSE__\u{2}", 0x01, 0x8400),
            ],
            [0xc8, 0x4b, 0xd6, 0x00, 0x00, 0x0b],
        );
        let rec = parse_response(&buf, Ipv4Addr::new(10, 0, 0, 41)).unwrap();
        assert_eq!(rec.name.as_deref(), Some("DESKTOP-7Q2LM"));
        assert_eq!(rec.group.as_deref(), Some("WORKGROUP"));
        assert_eq!(rec.mac.unwrap().to_string(), "c8:4b:d6:00:00:0b");
    }

    #[test]
    fn samba_server_name_without_mac() {
        let buf = response(&[entry("NAS", 0x20, 0x0400), entry("HOME", 0x00, 0x8400)], [0; 6]);
        let rec = parse_response(&buf, Ipv4Addr::new(10, 0, 0, 9)).unwrap();
        assert_eq!(rec.name.as_deref(), Some("NAS"));
        assert!(rec.mac.is_none());
    }

    #[test]
    fn macos_empty_name_table() {
        let buf = response(&[], [0x50, 0xa6, 0xd8, 0x00, 0x00, 0x08]);
        let rec = parse_response(&buf, Ipv4Addr::new(10, 0, 0, 73)).unwrap();
        assert!(rec.name.is_none());
        assert!(rec.mac.is_some());
    }

    #[test]
    fn rejects_queries_and_truncation() {
        let mut buf = response(&[entry("PC", 0x00, 0)], [0; 6]);
        buf[2] = 0; // not a response
        assert!(parse_response(&buf, Ipv4Addr::LOCALHOST).is_none());
        let buf = response(&[entry("PC", 0x00, 0)], [0; 6]);
        assert!(parse_response(&buf[..60], Ipv4Addr::LOCALHOST).is_none());
    }
}
