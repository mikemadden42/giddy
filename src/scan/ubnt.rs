//! Ubiquiti device discovery (UDP 10001): the protocol Ubiquiti access
//! points, switches and cameras answer so controllers can find them. A
//! broadcast request gets a reply of type-length-value fields with the
//! device's hostname, model, firmware and MAC. Sent from an ephemeral port,
//! so no privileges are needed.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use tokio::net::UdpSocket;

use super::{ScanEvent, Tx, UbntRecord, recv_for, sanitize};
use crate::device::MacAddr;
use crate::iface::Iface;

const PORT: u16 = 10001;
/// Version 1 and version 2 discovery requests: version, command, zero length.
/// Older firmware answers only v1, some newer only v2.
const REQUESTS: [[u8; 4]; 2] = [[1, 0, 0, 0], [2, 8, 0, 0]];

const TLV_MAC: u8 = 0x01;
const TLV_FIRMWARE: u8 = 0x03;
const TLV_HOSTNAME: u8 = 0x0b;
const TLV_PLATFORM: u8 = 0x0c;
const TLV_MODEL: u8 = 0x14;
const TLV_MODEL_SHORT: u8 = 0x15;

pub async fn query(iface: &Iface, tx: &Tx) -> anyhow::Result<()> {
    let sock = UdpSocket::bind(SocketAddrV4::new(iface.ip, 0)).await?;
    sock.set_broadcast(true)?;
    // A second pass covers lost datagrams; it's UDP.
    for window in [1500, 1500] {
        for dst in [iface.broadcast(), Ipv4Addr::BROADCAST] {
            for req in &REQUESTS {
                let _ = sock.send_to(req, SocketAddrV4::new(dst, PORT)).await;
            }
        }
        recv_for(&sock, Duration::from_millis(window), |buf, src| {
            if iface.contains(src)
                && let Some(rec) = parse_response(buf, src)
            {
                let _ = tx.send(ScanEvent::Ubiquiti(rec));
            }
        })
        .await;
    }
    Ok(())
}

/// Header: version (1 or 2), command, payload length (big endian), then
/// fields of type (1 byte), length (2 bytes BE) and value.
fn parse_response(buf: &[u8], ip: Ipv4Addr) -> Option<UbntRecord> {
    if !matches!(buf.first(), Some(1 | 2)) {
        return None;
    }
    let len = u16::from_be_bytes([*buf.get(2)?, *buf.get(3)?]) as usize;
    // Our own (or another scanner's) requests have an empty payload.
    let mut fields = buf.get(4..4 + len).filter(|f| !f.is_empty())?;

    let mut rec = UbntRecord { ip, hostname: None, model: None, firmware: None, mac: None };
    let mut models: [Option<String>; 3] = Default::default();
    while fields.len() >= 3 {
        let kind = fields[0];
        let n = u16::from_be_bytes([fields[1], fields[2]]) as usize;
        let value = fields.get(3..3 + n)?;
        fields = &fields[3 + n..];
        let text = || {
            let s: String = sanitize(&String::from_utf8_lossy(value)).trim().chars().take(64).collect();
            (!s.is_empty()).then_some(s)
        };
        match kind {
            TLV_MAC if n == 6 => rec.mac = value.try_into().ok().map(MacAddr),
            TLV_FIRMWARE => rec.firmware = text(),
            TLV_HOSTNAME => rec.hostname = text(),
            TLV_MODEL => models[0] = text(),
            TLV_MODEL_SHORT => models[1] = text(),
            TLV_PLATFORM => models[2] = text(),
            _ => {}
        }
    }
    rec.model = models.into_iter().flatten().next();
    (rec.hostname.is_some() || rec.model.is_some() || rec.mac.is_some()).then_some(rec)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(kind: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![kind];
        out.extend(u16::try_from(value.len()).unwrap().to_be_bytes());
        out.extend(value);
        out
    }

    fn packet(version: u8, fields: &[Vec<u8>]) -> Vec<u8> {
        let body = fields.concat();
        let mut out = vec![version, 0];
        out.extend(u16::try_from(body.len()).unwrap().to_be_bytes());
        out.extend(body);
        out
    }

    #[test]
    fn parses_reply() {
        let ip = Ipv4Addr::new(172, 16, 26, 109);
        let buf = packet(
            1,
            &[
                tlv(TLV_MAC, &[0x80, 0x2a, 0xa8, 0x89, 0xb7, 0xe7]),
                tlv(0x02, &[0x80, 0x2a, 0xa8, 0x89, 0xb7, 0xe7, 172, 16, 26, 109]),
                tlv(TLV_FIRMWARE, b"BZ.qca956x.v6.6.77.15402.240104.1543"),
                tlv(TLV_HOSTNAME, b"chapel-uap"),
                tlv(TLV_PLATFORM, b"U7PG2"),
                tlv(TLV_MODEL, b"UAP-AC-Pro-Gen2"),
            ],
        );
        let rec = parse_response(&buf, ip).unwrap();
        assert_eq!(rec.hostname.as_deref(), Some("chapel-uap"));
        assert_eq!(rec.model.as_deref(), Some("UAP-AC-Pro-Gen2"));
        assert_eq!(rec.firmware.as_deref(), Some("BZ.qca956x.v6.6.77.15402.240104.1543"));
        assert_eq!(rec.mac.unwrap().to_string(), "80:2a:a8:89:b7:e7");

        // The platform code stands in when no model field is sent.
        let buf = packet(2, &[tlv(TLV_PLATFORM, b"U7PG2")]);
        assert_eq!(parse_response(&buf, ip).unwrap().model.as_deref(), Some("U7PG2"));
    }

    #[test]
    fn ignores_requests_and_garbage() {
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        for req in &REQUESTS {
            assert!(parse_response(req, ip).is_none());
        }
        assert!(parse_response(b"HTTP/1.1 200 OK", ip).is_none());
        // A field claiming more bytes than the packet holds.
        assert!(parse_response(&[1, 0, 0, 5, TLV_HOSTNAME, 0, 9, b'a', b'b'], ip).is_none());
        // Control characters can't reach the terminal.
        let buf = packet(1, &[tlv(TLV_HOSTNAME, b"ap\x1b[31m-1")]);
        assert_eq!(parse_response(&buf, ip).unwrap().hostname.as_deref(), Some("ap[31m-1"));
    }
}
