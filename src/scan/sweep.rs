//! Subnet sweep: poke every address with ordinary UDP datagrams and TCP
//! connection attempts. To send anything on the local link the kernel must
//! first resolve the target's MAC via ARP, so this fills the neighbor cache
//! for every live host — no raw sockets or root needed.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::banner;
use super::{ScanEvent, Tx, connect_from};
use crate::iface::Iface;

/// Hosts probed at once. Each uses one socket per TCP port, so keep this
/// well under typical file-descriptor limits.
const CONCURRENCY: usize = 64;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(800);
/// Common ports; a SYN-ACK or RST from any of them proves the host is up.
const TCP_PORTS: &[u16] = &[80, 443, 22, 445, 62078];
/// UDP discard: a harmless datagram that still requires ARP resolution to
/// send. (NetBIOS on 137 gets a real query from the netbios module.)
const UDP_PORTS: &[u16] = &[9];

/// Services whose banners were already read, kept across cycles so each is
/// only asked once per scan session.
#[derive(Default)]
pub struct State {
    grabbed: Mutex<HashSet<(Ipv4Addr, u16)>>,
}

impl State {
    fn first_visit(&self, ip: Ipv4Addr, port: u16) -> bool {
        self.grabbed.lock().is_ok_and(|mut seen| seen.insert((ip, port)))
    }
}

pub async fn run(iface: &Iface, tx: &Tx, state: &Arc<State>) -> anyhow::Result<()> {
    let targets = iface.sweep_targets();
    let total = targets.len();
    let src = iface.ip;
    let udp = Arc::new(UdpSocket::bind(SocketAddrV4::new(src, 0)).await?);
    let permits = Arc::new(Semaphore::new(CONCURRENCY));
    let done = Arc::new(AtomicUsize::new(0));
    let _ = tx.send(ScanEvent::SweepProgress { done: 0, total });

    let mut tasks = JoinSet::new();
    for ip in targets {
        let permit = permits.clone().acquire_owned().await?;
        let (udp, tx, done, state) = (udp.clone(), tx.clone(), done.clone(), state.clone());
        tasks.spawn(async move {
            probe(src, ip, &udp, &tx, &state).await;
            drop(permit);
            let done = done.fetch_add(1, Ordering::Relaxed) + 1;
            let _ = tx.send(ScanEvent::SweepProgress { done, total });
        });
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn probe(src: Ipv4Addr, ip: Ipv4Addr, udp: &UdpSocket, tx: &Tx, state: &State) {
    for port in UDP_PORTS {
        let _ = udp.send_to(&[0], SocketAddrV4::new(ip, *port)).await;
    }
    let attempts = TCP_PORTS.iter().map(|&port| async move {
        let res = tokio::time::timeout(CONNECT_TIMEOUT, connect_from(src, SocketAddrV4::new(ip, port))).await;
        match res {
            Ok(Ok(stream)) => {
                if state.first_visit(ip, port)
                    && let Some(banner) = banner::grab(stream, src, ip, port).await
                {
                    let _ = tx.send(ScanEvent::Banner { ip, banner });
                }
                Some(Some(port))
            }
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Some(None),
            _ => None,
        }
    });
    for result in futures_util::future::join_all(attempts).await.into_iter().flatten() {
        let _ = tx.send(ScanEvent::Alive { ip, open_port: result });
    }
}
