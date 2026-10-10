//! Discovery orchestration. Everything here runs without elevated
//! privileges: we only open ordinary UDP/TCP sockets and read the kernel's
//! neighbor (ARP) table.

mod arp;
mod banner;
mod dns;
mod mdns;
mod netbios;
mod rdns;
mod ssdp;
mod sweep;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinSet;

pub use banner::{Banner, HttpInfo};

use crate::device::MacAddr;
use crate::iface::Iface;

#[derive(Debug, Clone)]
pub struct MdnsRecord {
    pub ip: Ipv4Addr,
    pub hostname: Option<String>,
    pub instance: Option<String>,
    pub service: Option<String>,
    /// Friendly name from TXT data (e.g. Google Cast `fn=`).
    pub friendly: Option<String>,
    pub model: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SsdpRecord {
    pub ip: Ipv4Addr,
    pub server: Option<String>,
    pub location: Option<String>,
    pub st: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SsdpDescription {
    pub ip: Ipv4Addr,
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NetBiosRecord {
    pub ip: Ipv4Addr,
    /// `None` when the host answered with an empty name table, as macOS
    /// file sharing does; the reply alone still says it runs SMB.
    pub name: Option<String>,
    pub group: Option<String>,
    pub mac: Option<MacAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Task {
    Sweep,
    Mdns,
    Ssdp,
    NetBios,
}

#[derive(Debug, Clone)]
pub enum ScanEvent {
    /// An entry in the kernel neighbor table. `active` means the kernel has
    /// recently confirmed the device is reachable.
    Neighbor {
        ip: Ipv4Addr,
        mac: MacAddr,
        active: bool,
    },
    /// A TCP port answered (open or actively refused): the host is up.
    Alive {
        ip: Ipv4Addr,
        open_port: Option<u16>,
    },
    Mdns(MdnsRecord),
    Ssdp(SsdpRecord),
    SsdpDescription(SsdpDescription),
    NetBios(NetBiosRecord),
    /// What a service on an open port said about itself.
    Banner {
        ip: Ipv4Addr,
        banner: Banner,
    },
    ReverseDns {
        ip: Ipv4Addr,
        name: String,
    },
    SweepProgress {
        done: usize,
        total: usize,
    },
    TaskStarted(Task),
    TaskFinished(Task),
    CycleFinished {
        next_in: Duration,
    },
    Error(String),
}

pub type Tx = UnboundedSender<ScanEvent>;

/// Events tagged with the generation of the scanner that produced them, so
/// stragglers from a cancelled scan (e.g. after switching interface) can be
/// told apart.
pub type Tagged = (u64, ScanEvent);

#[derive(Debug, Clone)]
pub struct Config {
    pub interval: Duration,
    pub sweep: bool,
}

/// Run discovery on `iface` until the returned future is dropped/aborted.
/// Dropping it tears down all child tasks.
pub async fn run(iface: Iface, cfg: Config, generation: u64, out: UnboundedSender<Tagged>) {
    let mut background = JoinSet::new();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    background.spawn(async move {
        while let Some(ev) = rx.recv().await {
            if out.send((generation, ev)).is_err() {
                break;
            }
        }
    });
    let (rdns_tx, rdns_rx) = tokio::sync::mpsc::unbounded_channel();
    background.spawn(rdns::run(rdns_rx, tx.clone()));
    background.spawn(arp::poll(iface.clone(), tx.clone(), rdns_tx));
    background.spawn(mdns::listen_passive(iface.clone(), tx.clone()));
    background.spawn(ssdp::listen_passive(iface.clone(), tx.clone()));

    let mut ssdp_state = ssdp::State::default();
    let sweep_state = std::sync::Arc::new(sweep::State::default());
    loop {
        // NetBIOS asks only hosts with ARP entries, so it follows the sweep.
        let sweep_then_netbios = async {
            if cfg.sweep {
                tracked(&tx, Task::Sweep, sweep::run(&iface, &tx, &sweep_state)).await;
            }
            tracked(&tx, Task::NetBios, netbios::query(&iface, &tx)).await;
        };
        let mdns = tracked(&tx, Task::Mdns, mdns::query(&iface, &tx));
        let ssdp = tracked(&tx, Task::Ssdp, ssdp::search(&iface, &tx, &mut ssdp_state));
        tokio::join!(sweep_then_netbios, mdns, ssdp);
        let _ = tx.send(ScanEvent::CycleFinished { next_in: cfg.interval });
        tokio::time::sleep(cfg.interval).await;
    }
}

async fn tracked(tx: &Tx, task: Task, fut: impl Future<Output = anyhow::Result<()>>) {
    let _ = tx.send(ScanEvent::TaskStarted(task));
    if let Err(e) = fut.await {
        let _ = tx.send(ScanEvent::Error(format!("{task:?}: {e:#}")));
    }
    let _ = tx.send(ScanEvent::TaskFinished(task));
}

/// An ephemeral-port UDP socket on `iface` whose multicast goes out that
/// interface. Replies to our queries come straight back to it.
fn query_socket(iface: &Iface) -> anyhow::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_multicast_if_v4(&iface.ip)?;
    sock.set_multicast_ttl_v4(4)?;
    sock.set_nonblocking(true)?;
    sock.bind(&SocketAddrV4::new(iface.ip, 0).into())?;
    Ok(UdpSocket::from_std(sock.into())?)
}

/// Best-effort shared listener on a well-known multicast group/port, so we
/// also hear unsolicited announcements. Coexists with system daemons (avahi,
/// mDNSResponder) via `SO_REUSEADDR`/`SO_REUSEPORT`; failure is not fatal.
fn group_socket(iface: &Iface, group: Ipv4Addr, port: u16) -> anyhow::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
    sock.join_multicast_v4(&group, &iface.ip)?;
    sock.set_multicast_loop_v4(false)?;
    Ok(UdpSocket::from_std(sock.into())?)
}

/// Receive datagrams for `window`, handing each to `handle`.
async fn recv_for(sock: &UdpSocket, window: Duration, mut handle: impl FnMut(&[u8], Ipv4Addr)) {
    let deadline = tokio::time::Instant::now() + window;
    let mut buf = vec![0u8; 9000];
    loop {
        match tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await {
            Err(_) => break,
            Ok(Ok((n, std::net::SocketAddr::V4(from)))) => handle(&buf[..n], *from.ip()),
            // Transient errors (e.g. queued ICMP unreachables) shouldn't end the window.
            Ok(_) => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    }
}
