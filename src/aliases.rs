//! User-assigned device names, keyed by MAC and persisted to
//! `$XDG_CONFIG_HOME/giddy/aliases` (one `mac<TAB>alias` per line).

use std::collections::HashMap;
use std::fmt::Write;
use std::path::PathBuf;

use crate::device::MacAddr;

#[derive(Default)]
pub struct Aliases {
    path: Option<PathBuf>,
    map: HashMap<MacAddr, String>,
}

fn config_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))?;
    Some(base.join("giddy").join("aliases"))
}

impl Aliases {
    pub fn load() -> Self {
        let path = config_path();
        let map = path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|text| {
                text.lines()
                    .filter_map(|l| {
                        let (mac, alias) = l.split_once('\t')?;
                        Some((mac.trim().parse().ok()?, alias.trim().to_string()))
                    })
                    .filter(|(_, a): &(MacAddr, String)| !a.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        Aliases { path, map }
    }

    pub fn get(&self, mac: MacAddr) -> Option<&String> {
        self.map.get(&mac)
    }

    /// Set (or clear, when empty) an alias and save.
    pub fn set(&mut self, mac: MacAddr, alias: &str) -> std::io::Result<()> {
        let alias = alias.trim();
        if alias.is_empty() {
            self.map.remove(&mac);
        } else {
            self.map.insert(mac, alias.replace(['\t', '\n'], " "));
        }
        self.save()
    }

    fn save(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut entries: Vec<_> = self.map.iter().collect();
        entries.sort();
        let mut text = String::new();
        for (mac, alias) in entries {
            let _ = writeln!(text, "{mac}\t{alias}");
        }
        std::fs::write(path, text)
    }
}
