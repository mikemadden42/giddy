//! Multicast DNS / DNS-SD discovery.
//!
//! Queries are sent from an ephemeral port, which makes them "legacy
//! unicast" queries (RFC 6762 §6.7): responders reply directly to us, so no
//! privileged port or multicast group membership is needed. We additionally
//! try to share port 5353 to hear unsolicited announcements.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use super::dns::{self, Name, RData, Record};
use super::{MdnsRecord, ScanEvent, Tx, group_socket, query_socket, recv_for};
use crate::iface::Iface;

const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const PORT: u16 = 5353;
const META_QUERY: &str = "_services._dns-sd._udp.local";
/// Asked directly as well, since not every responder answers the meta-query.
const COMMON_SERVICES: &[&str] = &[
    "_device-info._tcp",
    "_workstation._tcp",
    "_companion-link._tcp",
    "_airplay._tcp",
    "_raop._tcp",
    "_googlecast._tcp",
    "_spotify-connect._tcp",
    "_ipp._tcp",
    "_printer._tcp",
    "_pdl-datastream._tcp",
    "_uscan._tcp",
    "_smb._tcp",
    "_ssh._tcp",
    "_http._tcp",
    "_hap._tcp",
    "_homekit._tcp",
    "_sleep-proxy._udp",
    "_amzn-wplay._tcp",
    "_sonos._tcp",
    "_matter._tcp",
    "_meshcop._udp",
    "_esphomelib._tcp",
    "_home-assistant._tcp",
    "_hue._tcp",
];
/// Questions per packet, keeping queries comfortably under one MTU.
const BATCH: usize = 16;

/// What a response told us that's worth asking about next.
#[derive(Default)]
struct FollowUp {
    service_types: Vec<Name>,
    unresolved: Vec<Name>,
}

/// One active discovery round (~7s).
pub async fn query(iface: &Iface, tx: &Tx) -> anyhow::Result<()> {
    let sock = query_socket(iface)?;
    let dest = SocketAddrV4::new(GROUP, PORT);
    let send = |questions: Vec<(Name, u16)>| {
        let sock = &sock;
        async move {
            for chunk in questions.chunks(BATCH) {
                let _ = sock.send_to(&dns::build_query(chunk, true), dest).await;
            }
        }
    };

    let mut asked: HashSet<String> = HashSet::new();
    let mut initial = vec![(Name::parse(META_QUERY), dns::TYPE_PTR)];
    initial.extend(COMMON_SERVICES.iter().map(|s| (Name::parse(&format!("{s}.local")), dns::TYPE_PTR)));
    asked.extend(initial.iter().map(|(n, _)| n.key()));

    let mut next = initial.clone();
    for (round, window) in [1500, 1500, 1500, 2500].into_iter().enumerate() {
        // Repeat the initial questions once, as multicast is lossy.
        if round == 1 {
            next.extend(initial.iter().cloned());
        }
        // Ask known neighbors for their names via reverse lookups.
        if round == 1 {
            let dev = iface.name.clone();
            let neighbors = tokio::task::spawn_blocking(move || super::arp::read(&dev)).await.unwrap_or_default();
            next.extend(neighbors.iter().filter(|e| iface.contains(e.ip)).map(|e| (reverse_name(e.ip), dns::TYPE_PTR)));
        }
        send(std::mem::take(&mut next)).await;

        let mut follow = FollowUp::default();
        recv_for(&sock, Duration::from_millis(window), |buf, src| {
            if let Some(records) = dns::parse_response(buf) {
                process(&records, src, iface, tx, &mut follow);
            }
        })
        .await;
        for name in follow.service_types {
            if asked.insert(name.key()) {
                next.push((name, dns::TYPE_PTR));
            }
        }
        for name in follow.unresolved {
            if asked.insert(name.key()) {
                next.push((name, dns::TYPE_ANY));
            }
        }
    }
    Ok(())
}

/// Listen for unsolicited announcements on the shared mDNS port, forever.
pub async fn listen_passive(iface: Iface, tx: Tx) {
    let Ok(sock) = group_socket(&iface, GROUP, PORT) else { return };
    loop {
        recv_for(&sock, Duration::from_secs(3600), |buf, src| {
            if let Some(records) = dns::parse_response(buf) {
                process(&records, src, &iface, &tx, &mut FollowUp::default());
            }
        })
        .await;
    }
}

fn reverse_name(ip: Ipv4Addr) -> Name {
    let o = ip.octets();
    Name::parse(&format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]))
}

fn parse_reverse(name: &Name) -> Option<Ipv4Addr> {
    let l = &name.0;
    if l.len() != 6 || !l[4].eq_ignore_ascii_case("in-addr") || !l[5].eq_ignore_ascii_case("arpa") {
        return None;
    }
    format!("{}.{}.{}.{}", l[3], l[2], l[1], l[0]).parse().ok()
}

/// Correlate the records in one response packet and emit per-device facts.
fn process(records: &[Record], src: Ipv4Addr, iface: &Iface, tx: &Tx, follow: &mut FollowUp) {
    let mut addrs: HashMap<String, Ipv4Addr> = HashMap::new();
    let mut srv: HashMap<String, Name> = HashMap::new();
    let mut txt: HashMap<String, &[String]> = HashMap::new();
    let mut instances: Vec<&Name> = Vec::new();
    let emit = |rec: MdnsRecord| {
        if iface.contains(rec.ip) {
            let _ = tx.send(ScanEvent::Mdns(rec));
        }
    };

    for r in records {
        match &r.data {
            RData::A(ip) => {
                addrs.insert(r.name.key(), *ip);
            }
            RData::Srv { target } => {
                srv.insert(r.name.key(), target.clone());
                instances.push(&r.name);
            }
            RData::Txt(strings) => {
                txt.insert(r.name.key(), strings);
            }
            RData::Ptr(target) if r.name.key() == META_QUERY => follow.service_types.push(target.clone()),
            RData::Ptr(target) => {
                if let Some(ip) = parse_reverse(&r.name) {
                    emit(MdnsRecord::host(ip, target.host()));
                } else if target.split_instance().is_some() {
                    instances.push(target);
                }
            }
            RData::Other => {}
        }
    }

    for (name, ip) in &addrs {
        emit(MdnsRecord::host(*ip, Name::parse(name).host()));
    }

    let mut seen = HashSet::new();
    for inst in instances {
        let key = inst.key();
        if !seen.insert(key.clone()) {
            continue;
        }
        let Some((instance, service)) = inst.split_instance() else { continue };
        let target = srv.get(&key);
        if target.is_none() {
            follow.unresolved.push(inst.clone());
        }
        let ip = target.and_then(|t| addrs.get(&t.key()).copied()).unwrap_or(src);
        let txt = txt.get(&key).copied().unwrap_or_default();
        let get = |k: &str| {
            txt.iter().find_map(|kv| {
                let (key, value) = kv.split_once('=')?;
                (key.eq_ignore_ascii_case(k) && !value.trim().is_empty()).then(|| value.trim().to_string())
            })
        };
        emit(MdnsRecord {
            ip,
            hostname: target.map(Name::host),
            friendly: get("fn"),
            model: get("md").or_else(|| get("model")).or_else(|| get("ty")).or_else(|| get("usb_MDL")),
            instance: Some(instance),
            service: Some(service),
        });
    }
}

impl MdnsRecord {
    fn host(ip: Ipv4Addr, hostname: String) -> Self {
        MdnsRecord { ip, hostname: Some(hostname), instance: None, service: None, friendly: None, model: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_names_round_trip() {
        let ip = Ipv4Addr::new(10, 0, 0, 72);
        assert_eq!(reverse_name(ip).key(), "72.0.0.10.in-addr.arpa");
        assert_eq!(parse_reverse(&reverse_name(ip)), Some(ip));
    }

    #[test]
    fn correlates_ptr_srv_txt_a() {
        let iface = Iface { name: "t".into(), ip: [10, 0, 0, 2].into(), prefix: 24, mac: None, gateway: None };
        let inst = Name::parse("Living Room._googlecast._tcp.local");
        let host = Name::parse("abc123.local");
        let records = vec![
            Record { name: Name::parse("_googlecast._tcp.local"), data: RData::Ptr(inst.clone()) },
            Record { name: inst.clone(), data: RData::Srv { target: host.clone() } },
            Record { name: inst.clone(), data: RData::Txt(vec!["md=Chromecast".into(), "fn=TV".into()]) },
            Record { name: host, data: RData::A([10, 0, 0, 60].into()) },
        ];
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut follow = FollowUp::default();
        process(&records, [10, 0, 0, 99].into(), &iface, &tx, &mut follow);
        let mut found = None;
        while let Ok(ScanEvent::Mdns(rec)) = rx.try_recv() {
            if rec.service.is_some() {
                found = Some(rec);
            }
        }
        let rec = found.unwrap();
        assert_eq!(rec.ip, Ipv4Addr::new(10, 0, 0, 60));
        assert_eq!(rec.instance.as_deref(), Some("Living Room"));
        assert_eq!(rec.friendly.as_deref(), Some("TV"));
        assert_eq!(rec.model.as_deref(), Some("Chromecast"));
        assert_eq!(follow.unresolved, Vec::<Name>::new());
    }
}
