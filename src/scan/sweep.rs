//! Subnet sweep, in two phases. First a single UDP datagram to every
//! address: to send anything on the local link the kernel must resolve the
//! target's MAC via ARP, so this fills the neighbor cache for every live
//! host, with no raw sockets or root needed. Then TCP connection attempts,
//! only to the hosts that answered ARP, to learn open ports and banners.
//!
//! Large ranges go in chunks: each chunk's neighbor entries are read soon
//! after its datagrams settle, while the next chunk is being sent, because
//! the kernel's neighbor table is small (1,024 entries by default on Linux)
//! and would otherwise evict live hosts before we read them.

use std::collections::{HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::Instant;

use super::banner;
use super::{ScanEvent, Tx, connect_from};
use crate::iface::{Cidr, Iface};

/// Hosts probed at once. Each uses one socket per TCP port, so keep this
/// well under typical file-descriptor limits. This caps open sockets; the
/// packet rate is limited separately by [`Pacer`], since hosts that refuse
/// instantly would otherwise free slots fast enough to burst.
const CONCURRENCY: usize = 64;
/// How long to wait after the last datagram for ARP replies to arrive.
const ARP_SETTLE: Duration = Duration::from_millis(1500);
/// Addresses per chunk: well under the neighbor table's size.
const CHUNK: usize = 256;
/// Report phase-one progress every this many addresses, not every one.
const PROGRESS_EVERY: usize = 32;
/// Back-pressure never slows the sweep below this many packets per second.
const MIN_RATE: u32 = 10;
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

/// Spaces probe packets (UDP datagrams and TCP connection attempts) to at
/// most `rate` per second, without bursting to catch up after a pause.
/// Halves the rate when the OS signals back-pressure.
struct Pacer {
    inner: Mutex<PacerState>,
}

struct PacerState {
    next: Instant,
    gap: Duration,
    slowed_at: Option<Instant>,
}

impl Pacer {
    fn new(rate: u32) -> Self {
        let gap = Duration::from_secs(1) / rate.max(1);
        Pacer { inner: Mutex::new(PacerState { next: Instant::now(), gap, slowed_at: None }) }
    }

    /// Wait for this packet's turn.
    async fn wait(&self) {
        let at = {
            let mut s = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let at = s.next.max(Instant::now());
            s.next = at + s.gap;
            at
        };
        tokio::time::sleep_until(at).await;
    }

    /// Halve the rate, at most once a second so one burst of errors counts
    /// once. Returns the new rate (packets per second) if it changed.
    fn back_off(&self) -> Option<u32> {
        let mut s = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        if s.slowed_at.is_some_and(|t| now.duration_since(t) < Duration::from_secs(1)) {
            return None;
        }
        let slowest = Duration::from_secs(1) / MIN_RATE;
        if s.gap >= slowest {
            return None;
        }
        s.gap = (s.gap * 2).min(slowest);
        s.slowed_at = Some(now);
        u32::try_from(Duration::from_secs(1).as_nanos() / s.gap.as_nanos().max(1)).ok()
    }

    fn on_error(&self, e: &std::io::Error, tx: &Tx) {
        if is_backpressure(e)
            && let Some(rate) = self.back_off()
        {
            let _ = tx.send(ScanEvent::Error(format!("Network is pushing back; sweep slowed to {rate} packets/s")));
        }
    }
}

/// The OS is out of buffer space or neighbor-table room: we're sending
/// faster than it, or the network, can take.
fn is_backpressure(e: &std::io::Error) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const ENOBUFS: i32 = 105;
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
    const ENOBUFS: i32 = 55;
    #[cfg(windows)]
    const ENOBUFS: i32 = 10055; // WSAENOBUFS
    e.kind() == std::io::ErrorKind::OutOfMemory || e.raw_os_error() == Some(ENOBUFS)
}

pub async fn run(iface: &Iface, tx: &Tx, state: &Arc<State>, rate: u32, range: Option<Cidr>) -> anyhow::Result<()> {
    let targets = match range {
        Some(r) if iface.covers(r) => iface.targets_in(r),
        Some(r) => {
            let _ =
                tx.send(ScanEvent::Error(format!("--sweep {r} is not on {}; sweeping its default range", iface.name)));
            iface.sweep_targets()
        }
        None => iface.sweep_targets(),
    };
    let src = iface.ip;
    let udp = UdpSocket::bind(SocketAddrV4::new(src, 0)).await?;
    let pacer = Arc::new(Pacer::new(rate));
    let permits = Arc::new(Semaphore::new(CONCURRENCY));
    // Progress counts datagram addresses plus TCP hosts; the total grows as
    // live hosts are found.
    let total = Arc::new(AtomicUsize::new(targets.len()));
    let done = Arc::new(AtomicUsize::new(0));
    let report = |tx: &Tx, done: &AtomicUsize, total: &AtomicUsize| {
        let _ = tx.send(ScanEvent::SweepProgress {
            done: done.load(Ordering::Relaxed),
            total: total.load(Ordering::Relaxed),
        });
    };
    report(tx, &done, &total);

    let mut tasks = JoinSet::new();
    let mut probe_chunk = |hosts: Vec<Ipv4Addr>| {
        total.fetch_add(hosts.len(), Ordering::Relaxed);
        for ip in hosts {
            let (tx, done, total, state, pacer, permits) =
                (tx.clone(), done.clone(), total.clone(), state.clone(), pacer.clone(), permits.clone());
            tasks.spawn(async move {
                let Ok(_permit) = permits.acquire_owned().await else { return };
                probe_tcp(src, ip, &tx, &state, &pacer).await;
                done.fetch_add(1, Ordering::Relaxed);
                report(&tx, &done, &total);
            });
        }
    };

    // Phase 1 sends each chunk's datagrams; once a chunk has settled, phase 2
    // reads its neighbor entries and starts TCP probes, while later chunks
    // are still being sent.
    let mut settling: VecDeque<(Instant, &[Ipv4Addr])> = VecDeque::new();
    for chunk in targets.chunks(CHUNK) {
        for &ip in chunk {
            for port in UDP_PORTS {
                pacer.wait().await;
                if let Err(e) = udp.send_to(&[0], SocketAddrV4::new(ip, *port)).await {
                    pacer.on_error(&e, tx);
                }
            }
            if done.fetch_add(1, Ordering::Relaxed).is_multiple_of(PROGRESS_EVERY) {
                report(tx, &done, &total);
            }
        }
        settling.push_back((Instant::now() + ARP_SETTLE, chunk));
        while settling.front().is_some_and(|(due, _)| *due <= Instant::now()) {
            let (_, settled) = settling.pop_front().expect("checked non-empty");
            probe_chunk(resolved(iface, settled).await);
        }
    }
    for (due, settled) in settling {
        tokio::time::sleep_until(due).await;
        probe_chunk(resolved(iface, settled).await);
    }
    report(tx, &done, &total);
    while tasks.join_next().await.is_some() {}
    Ok(())
}

/// The addresses in `chunk` that now have a MAC in the neighbor table. If
/// the table can't be read at all (macOS without the signed bundle ID), all
/// of `chunk`, so TCP probing still covers it.
async fn resolved(iface: &Iface, chunk: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    let name = iface.name.clone();
    let entries = tokio::task::spawn_blocking(move || super::arp::read(&name)).await.unwrap_or_default();
    if entries.is_empty() {
        return chunk.to_vec();
    }
    let known: HashSet<Ipv4Addr> = entries.into_iter().map(|e| e.ip).collect();
    chunk.iter().copied().filter(|ip| known.contains(ip)).collect()
}

async fn probe_tcp(src: Ipv4Addr, ip: Ipv4Addr, tx: &Tx, state: &State, pacer: &Pacer) {
    let attempts = TCP_PORTS.iter().map(|&port| async move {
        pacer.wait().await;
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
            Ok(Err(e)) => {
                pacer.on_error(&e, tx);
                None
            }
            Err(_) => None,
        }
    });
    for result in futures_util::future::join_all(attempts).await.into_iter().flatten() {
        let _ = tx.send(ScanEvent::Alive { ip, open_port: result });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pacer_spaces_packets() {
        let pacer = Pacer::new(200); // 5 ms apart
        let start = Instant::now();
        for _ in 0..11 {
            pacer.wait().await;
        }
        assert!(start.elapsed() >= Duration::from_millis(50));
    }

    #[test]
    fn back_off_halves_once_per_second_down_to_the_floor() {
        let pacer = Pacer::new(100);
        assert_eq!(pacer.back_off(), Some(50));
        assert_eq!(pacer.back_off(), None); // within the same second
        pacer.inner.lock().unwrap().slowed_at = None;
        assert_eq!(pacer.back_off(), Some(25));
        pacer.inner.lock().unwrap().slowed_at = None;
        assert_eq!(pacer.back_off(), Some(12)); // 12.5, rounded down
        pacer.inner.lock().unwrap().slowed_at = None;
        assert_eq!(pacer.back_off(), Some(MIN_RATE));
        pacer.inner.lock().unwrap().slowed_at = None;
        assert_eq!(pacer.back_off(), None);
    }

    #[test]
    fn detects_backpressure() {
        assert!(is_backpressure(&std::io::Error::from(std::io::ErrorKind::OutOfMemory)));
        assert!(!is_backpressure(&std::io::Error::from(std::io::ErrorKind::ConnectionRefused)));
    }
}
