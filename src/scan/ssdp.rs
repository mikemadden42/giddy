//! SSDP / UPnP discovery. M-SEARCH replies are unicast back to our
//! ephemeral port; device description XML is fetched over plain HTTP.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

use super::{ScanEvent, SsdpDescription, SsdpRecord, Tx, group_socket, query_socket, recv_for};
use crate::iface::Iface;

const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const PORT: u16 = 1900;
const SEARCH_TARGETS: &[&str] = &["ssdp:all", "upnp:rootdevice"];
const MAX_DESCRIPTION: usize = 256 * 1024;

/// Description URLs already fetched, kept across cycles.
#[derive(Default)]
pub struct State {
    fetched: HashSet<String>,
}

pub async fn search(iface: &Iface, tx: &Tx, state: &mut State) -> anyhow::Result<()> {
    let sock = query_socket(iface)?;
    let dest = SocketAddrV4::new(GROUP, PORT);
    let mut fetches = JoinSet::new();
    for _ in 0..2 {
        for st in SEARCH_TARGETS {
            let msg = format!(
                "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {st}\r\n\r\n"
            );
            let _ = sock.send_to(msg.as_bytes(), dest).await;
        }
        recv_for(&sock, Duration::from_millis(2000), |buf, src| {
            if let Some(rec) = handle(buf, src, iface, tx)
                && let Some(loc) = rec.location
                && state.fetched.insert(loc.clone())
            {
                let (tx, iface) = (tx.clone(), iface.clone());
                fetches.spawn(async move {
                    let fetch = describe(&loc, rec.ip, &iface);
                    if let Ok(Ok(desc)) = tokio::time::timeout(Duration::from_secs(4), fetch).await {
                        let _ = tx.send(ScanEvent::SsdpDescription(desc));
                    }
                });
            }
        })
        .await;
    }
    while fetches.join_next().await.is_some() {}
    Ok(())
}

/// Hear NOTIFY announcements on the shared SSDP port, forever. Their
/// descriptions get fetched on the next active search.
pub async fn listen_passive(iface: Iface, tx: Tx) {
    let Ok(sock) = group_socket(&iface, GROUP, PORT) else { return };
    loop {
        recv_for(&sock, Duration::from_secs(3600), |buf, src| {
            handle(buf, src, &iface, &tx);
        })
        .await;
    }
}

fn handle(buf: &[u8], src: Ipv4Addr, iface: &Iface, tx: &Tx) -> Option<SsdpRecord> {
    let text = std::str::from_utf8(buf).ok()?;
    let first = text.lines().next()?;
    if !(first.starts_with("HTTP/1.1 200") || first.starts_with("NOTIFY")) || !iface.contains(src) {
        return None;
    }
    let header = |name: &str| {
        text.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k.trim().eq_ignore_ascii_case(name) && !v.trim().is_empty()).then(|| v.trim().to_string())
        })
    };
    if header("NTS").is_some_and(|nts| nts.contains("byebye")) {
        return None;
    }
    let rec = SsdpRecord {
        ip: src,
        server: header("SERVER"),
        location: header("LOCATION"),
        st: header("ST").or(header("NT")),
    };
    let _ = tx.send(ScanEvent::Ssdp(rec.clone()));
    Some(rec)
}

/// Fetch a UPnP device description and pull out the interesting fields.
/// Only literal addresses on the local subnet are contacted, so a device
/// can't point us at arbitrary hosts.
async fn describe(location: &str, ip: Ipv4Addr, iface: &Iface) -> anyhow::Result<SsdpDescription> {
    let rest = location.strip_prefix("http://").ok_or_else(|| anyhow::anyhow!("not http"))?;
    let (authority, path) = rest.split_once('/').map_or((rest, "/".to_string()), |(a, p)| (a, format!("/{p}")));
    let (host, port) = authority.split_once(':').unwrap_or((authority, "80"));
    let host: Ipv4Addr = host.parse()?;
    anyhow::ensure!(iface.contains(host), "description host off-subnet");
    let mut stream = TcpStream::connect((host, port.parse::<u16>()?)).await?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {authority}\r\nUser-Agent: giddy\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;
    let mut body = Vec::new();
    stream.take(MAX_DESCRIPTION as u64).read_to_end(&mut body).await?;
    let text = String::from_utf8_lossy(&body);
    Ok(SsdpDescription {
        ip,
        friendly_name: xml_tag(&text, "friendlyName"),
        manufacturer: xml_tag(&text, "manufacturer"),
        model: xml_tag(&text, "modelName").or_else(|| xml_tag(&text, "modelDescription")),
    })
}

/// First `<tag>…</tag>` value (tolerating namespace prefixes), entity-decoded.
fn xml_tag(text: &str, tag: &str) -> Option<String> {
    let open = text.find(&format!("{tag}>"))? + tag.len() + 1;
    let value = &text[open..open + text[open..].find('<')?];
    let value = value
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'");
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_description() {
        let xml = "<root><device><deviceType>x</deviceType><friendlyName>Living Room &amp; Den</friendlyName>\
                   <manufacturer>Sonos, Inc.</manufacturer><modelName>One</modelName></device></root>";
        assert_eq!(xml_tag(xml, "friendlyName").as_deref(), Some("Living Room & Den"));
        assert_eq!(xml_tag(xml, "manufacturer").as_deref(), Some("Sonos, Inc."));
        assert_eq!(xml_tag(xml, "modelNumber"), None);
    }

    #[test]
    fn parses_search_reply() {
        let iface = Iface { name: "t".into(), ip: [10, 0, 0, 2].into(), prefix: 24, mac: None, gateway: None };
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let reply = b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: upnp:rootdevice\r\n\
                      LOCATION: http://10.0.0.1:5000/rootDesc.xml\r\nSERVER: Linux UPnP/1.1 MiniUPnPd/2.1\r\n\r\n";
        let rec = handle(reply, [10, 0, 0, 1].into(), &iface, &tx).unwrap();
        assert_eq!(rec.location.as_deref(), Some("http://10.0.0.1:5000/rootDesc.xml"));
        assert_eq!(rec.st.as_deref(), Some("upnp:rootdevice"));
        assert!(handle(reply, [192, 168, 1, 1].into(), &iface, &tx).is_none());
    }
}
