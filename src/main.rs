//! giddy — see who's on your network, without root.

mod aliases;
mod app;
mod device;
mod iface;
mod oui;
mod scan;
mod ui;

use std::time::Duration;

use anyhow::{Context, bail};
use clap::Parser;
use crossterm::event::EventStream;
use futures_util::StreamExt;
use tokio::sync::mpsc::{self, UnboundedReceiver};

use crate::app::App;

#[derive(Parser)]
#[command(version, about = "Discover devices on your local network without elevated privileges")]
struct Args {
    /// Network interface to scan (defaults to the one with the default route)
    #[arg(short, long)]
    interface: Option<String>,

    /// Seconds between discovery rounds
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(5..))]
    interval: u64,

    /// Skip the subnet sweep; rely on mDNS, SSDP and the existing ARP cache
    #[arg(long)]
    no_sweep: bool,

    /// List usable interfaces and exit
    #[arg(long)]
    list_interfaces: bool,

    /// Run one discovery round, print the results as text and exit
    #[arg(long)]
    once: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let ifaces = iface::list();
    if args.list_interfaces {
        let default = iface::default_index(&ifaces);
        for (i, iface) in ifaces.iter().enumerate() {
            let mark = if Some(i) == default { "*" } else { " " };
            println!("{mark} {:<18} {}", iface.name, iface.cidr());
        }
        return Ok(());
    }
    if ifaces.is_empty() {
        bail!("no usable IPv4 interfaces found");
    }
    let idx = match &args.interface {
        Some(name) => ifaces
            .iter()
            .position(|i| &i.name == name)
            .with_context(|| format!("interface {name:?} not found (try --list-interfaces)"))?,
        None => iface::default_index(&ifaces).unwrap_or(0),
    };

    let cfg = scan::Config { interval: Duration::from_secs(args.interval), sweep: !args.no_sweep };
    let (tx, rx) = mpsc::unbounded_channel();
    let mut app = App::new(ifaces, idx, cfg, tx);
    oui::warm_up();

    if args.once {
        return run_once(app, rx).await;
    }

    let mut terminal = ratatui::init();
    app.start_scan();
    let result = run(&mut terminal, &mut app, rx).await;
    ratatui::restore();
    result
}

async fn run(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    mut rx: UnboundedReceiver<scan::Tagged>,
) -> anyhow::Result<()> {
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(200));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    while !app.quit {
        terminal.draw(|f| ui::draw(f, app))?;
        tokio::select! {
            ev = events.next() => match ev {
                Some(Ok(ev)) => app.on_terminal_event(ev),
                Some(Err(e)) => return Err(e.into()),
                None => break,
            },
            Some(ev) = rx.recv() => {
                app.on_scan(ev);
                // Apply everything that's queued before redrawing.
                while let Ok(ev) = rx.try_recv() {
                    app.on_scan(ev);
                }
                app.rebuild_view();
            }
            _ = tick.tick() => app.on_tick(),
        }
    }
    Ok(())
}

/// Headless mode: one discovery round, then a plain-text table.
async fn run_once(mut app: App, mut rx: UnboundedReceiver<scan::Tagged>) -> anyhow::Result<()> {
    let iface = app.current_iface().clone();
    eprintln!("scanning {} ({})…", iface.name, iface.cidr());
    app.start_scan();
    while let Some(ev) = rx.recv().await {
        let done = matches!(ev.1, scan::ScanEvent::CycleFinished { .. });
        app.on_scan(ev);
        if done {
            break;
        }
    }
    // Let the ARP poller pick up the last resolutions.
    let settle = tokio::time::sleep(Duration::from_millis(1500));
    tokio::pin!(settle);
    loop {
        tokio::select! {
            _ = &mut settle => break,
            Some(ev) = rx.recv() => app.on_scan(ev),
        }
    }
    app.rebuild_view();
    println!("{:<15}  {:<32}  {:<17}  MANUFACTURER", "IP", "NAME", "MAC");
    for d in app.view.iter().filter_map(|ip| app.devices.get(ip)) {
        let name: String = d.display_name().unwrap_or("-").chars().take(32).collect();
        let mac = d.mac.map(|m| m.to_string()).unwrap_or_else(|| "-".into());
        let vendor = d.manufacturer().unwrap_or(if d.mac.is_some_and(|m| m.is_local()) { "(private)" } else { "" });
        println!("{:<15}  {:<32}  {:<17}  {}", d.ip, name, mac, vendor);
    }
    Ok(())
}
