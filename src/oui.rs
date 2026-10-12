//! Manufacturer lookup by MAC address prefix (IEEE OUI / MA-M / MA-S).
//!
//! The table is generated from Wireshark's `manuf` database by
//! `scripts/update-oui.sh` and embedded gzipped into the binary.

use std::collections::HashMap;
use std::io::Read;
use std::sync::OnceLock;

use crate::device::MacAddr;

static OUI_GZ: &[u8] = include_bytes!("../data/oui.tsv.gz");

/// Prefix (as an integer of `bits` length) -> manufacturer, one map per prefix length.
struct Table {
    /// Sorted longest prefix first: (prefix length in bits, entries).
    levels: Vec<(u32, HashMap<u64, Box<str>>)>,
}

fn table() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut text = String::new();
        let _ = flate2::read::GzDecoder::new(OUI_GZ).read_to_string(&mut text);
        let mut by_bits: HashMap<u32, HashMap<u64, Box<str>>> = HashMap::new();
        for line in text.lines() {
            let Some((hex, name)) = line.split_once('\t') else { continue };
            let Ok(prefix) = u64::from_str_radix(hex, 16) else { continue };
            let Ok(bits) = u32::try_from(hex.len() * 4) else { continue };
            by_bits.entry(bits).or_default().insert(prefix, name.into());
        }
        let mut levels: Vec<_> = by_bits.into_iter().collect();
        levels.sort_by_key(|(bits, _)| std::cmp::Reverse(*bits));
        Table { levels }
    })
}

/// Load the table up front so the first lookup doesn't stall the UI.
pub fn warm_up() {
    table();
}

/// Look up the registered manufacturer for a MAC address, preferring the
/// most specific (longest) assignment.
pub fn lookup(mac: MacAddr) -> Option<&'static str> {
    let value = mac.0.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
    table().levels.iter().find_map(|(bits, map)| map.get(&(value >> (48 - bits))).map(|s| &**s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vendors() {
        let apple = MacAddr([0xe0, 0x89, 0x7e, 0x00, 0x00, 0x0a]);
        assert_eq!(lookup(apple), Some("Apple, Inc."));
        // MA-S block inside 00:50:C2
        let tls = MacAddr([0x00, 0x50, 0xc2, 0x00, 0x0f, 0xff]);
        assert_eq!(lookup(tls), Some("T.L.S. Corp."));
    }
}
