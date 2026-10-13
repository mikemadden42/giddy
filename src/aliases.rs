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
        // Write a temporary file and rename it over the old one, so a crash
        // or full disk mid-save can't leave the aliases file empty or cut off.
        let tmp = path.with_file_name(format!("aliases.{}.tmp", std::process::id()));
        std::fs::write(&tmp, text).and_then(|()| std::fs::rename(&tmp, path)).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saves_and_reloads() {
        let dir = std::env::temp_dir().join(format!("giddy-aliases-test-{}", std::process::id()));
        let path = dir.join("giddy").join("aliases");
        let mut aliases = Aliases { path: Some(path.clone()), map: HashMap::new() };
        let mac = MacAddr([2, 0, 0, 0, 0, 1]);
        aliases.set(mac, "Office printer").unwrap();
        aliases.set(MacAddr([2, 0, 0, 0, 0, 2]), "tab\there").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, "02:00:00:00:00:01\tOffice printer\n02:00:00:00:00:02\ttab here\n");
        // No temporary file left behind.
        assert_eq!(std::fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
        aliases.set(mac, "").unwrap();
        assert!(!std::fs::read_to_string(&path).unwrap().contains("Office"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
