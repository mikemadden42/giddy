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
use tokio::time::Instant;

use super::banner;
use super::{ScanEvent, Tx, connect_from};
use crate::iface::Iface;

/// Hosts probed at once. Each uses one socket per TCP port, so keep this
/// well under typical file-descriptor limits. This caps open sockets; the
/// packet rate is limited separately by [`Pacer`], since hosts that refuse
/// instantly would otherwise free slots fast enough to burst.
const CONCURRENCY: usize = 64;
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

pub async fn run(iface: &Iface, tx: &Tx, state: &Arc<State>, rate: u32) -> anyhow::Result<()> {
    let targets = iface.sweep_targets();
    let total = targets.len();
    let src = iface.ip;
    let udp = Arc::new(UdpSocket::bind(SocketAddrV4::new(src, 0)).await?);
    let permits = Arc::new(Semaphore::new(CONCURRENCY));
    let pacer = Arc::new(Pacer::new(rate));
    let done = Arc::new(AtomicUsize::new(0));
    let _ = tx.send(ScanEvent::SweepProgress { done: 0, total });

    let mut tasks = JoinSet::new();
    for ip in targets {
        let permit = permits.clone().acquire_owned().await?;
        let (udp, tx, done, state, pacer) = (udp.clone(), tx.clone(), done.clone(), state.clone(), pacer.clone());
        tasks.spawn(async move {
            probe(src, ip, &udp, &tx, &state, &pacer).await;
            drop(permit);
            let done = done.fetch_add(1, Ordering::Relaxed) + 1;
            let _ = tx.send(ScanEvent::SweepProgress { done, total });
        });
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn probe(src: Ipv4Addr, ip: Ipv4Addr, udp: &UdpSocket, tx: &Tx, state: &State, pacer: &Pacer) {
    for port in UDP_PORTS {
        pacer.wait().await;
        if let Err(e) = udp.send_to(&[0], SocketAddrV4::new(ip, *port)).await {
            pacer.on_error(&e, tx);
        }
    }
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
