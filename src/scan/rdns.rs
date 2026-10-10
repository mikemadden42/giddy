//! Reverse DNS via the system resolver (often the router knows DHCP names).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task::JoinSet;

use super::{ScanEvent, Tx};

pub async fn run(mut rx: UnboundedReceiver<Ipv4Addr>, tx: Tx) {
    let mut asked = HashSet::new();
    let permits = Arc::new(Semaphore::new(8));
    let mut lookups = JoinSet::new();
    while let Some(ip) = rx.recv().await {
        if !asked.insert(ip) {
            continue;
        }
        let Ok(permit) = permits.clone().acquire_owned().await else { break };
        let tx = tx.clone();
        lookups.spawn(async move {
            let name = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&IpAddr::V4(ip))).await;
            drop(permit);
            if let Ok(Ok(name)) = name {
                let name = name.trim_end_matches('.').to_string();
                // Skip synthesized names like systemd-resolved's `_gateway`.
                if !name.is_empty() && !name.starts_with('_') && name.parse::<IpAddr>().is_err() {
                    let _ = tx.send(ScanEvent::ReverseDns { ip, name });
                }
            }
        });
        while lookups.try_join_next().is_some() {}
    }
}
