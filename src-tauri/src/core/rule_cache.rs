//! Compiled-ruleset cache.
//!
//! Compiling thousands of YARA rules at every startup is wasteful for a
//! kiosk app whose rules change infrequently. yara-x natively supports
//! serializing/deserializing a `Rules` struct to a versioned binary blob
//! (the same format the `yr compile` CLI emits), so we cache it next to
//! the rules dir and load it on subsequent launches.
//!
//! Cache invalidation: every mutating command (toggle, edit, fetch,
//! import, add/remove source) calls `commands::reload_rules`, which
//! writes a fresh cache. For external edits to the rule files, the
//! startup loader does a mtime sanity check against the rules directory
//! and the two config JSON files. yara-x's `deserialize` also carries
//! a magic + version header, so a yara-x crate bump or a corrupted
//! file falls through to a clean recompile automatically.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Context;
use walkdir::WalkDir;
use yara_x::Rules;

pub const CACHE_FILENAME: &str = "rules.bin";

pub struct RuleCache {
    pub path: PathBuf,
}

impl RuleCache {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join(CACHE_FILENAME),
        }
    }

    /// Try to load the cached compiled ruleset. Returns `None` when the
    /// cache is missing, stale, on a different yara-x version, or fails
    /// to deserialize — in all those cases the caller should recompile.
    pub fn try_load(
        &self,
        rules_dir: &Path,
        sources_json: &Path,
        disabled_json: &Path,
    ) -> Option<Rules> {
        if !self.path.exists() {
            return None;
        }

        let cache_mtime = std::fs::metadata(&self.path)
            .ok()
            .and_then(|m| m.modified().ok())?;

        if self.is_stale(cache_mtime, rules_dir, sources_json, disabled_json) {
            log::info!("Rule cache is stale, will recompile");
            return None;
        }

        match std::fs::read(&self.path) {
            Ok(bytes) => match Rules::deserialize(&bytes) {
                Ok(rules) => {
                    log::info!(
                        "Loaded compiled rules from cache ({} bytes)",
                        bytes.len()
                    );
                    Some(rules)
                }
                Err(e) => {
                    // yara-x version bump or file corruption — drop the
                    // bad cache so we don't keep retrying it.
                    log::warn!("Rule cache failed to deserialize (will recompile): {}", e);
                    let _ = std::fs::remove_file(&self.path);
                    None
                }
            },
            Err(e) => {
                log::warn!("Failed to read rule cache: {}", e);
                None
            }
        }
    }

    /// Atomically write the cache via temp + rename so a crash mid-write
    /// can't leave a half-serialized blob in place.
    pub fn write(&self, rules: &Rules) -> anyhow::Result<()> {
        let bytes = rules.serialize().context("yara-x serialize failed")?;
        let tmp = self.path.with_extension("bin.tmp");
        std::fs::write(&tmp, &bytes).context("writing rule cache tmp file")?;
        std::fs::rename(&tmp, &self.path).context("renaming rule cache tmp file")?;
        log::info!("Wrote rule cache ({} bytes)", bytes.len());
        Ok(())
    }

    /// Delete the cache file. Used when the user removes all sources or
    /// otherwise explicitly invalidates state.
    pub fn invalidate(&self) {
        let _ = std::fs::remove_file(&self.path);
    }

    fn is_stale(
        &self,
        cache_mtime: SystemTime,
        rules_dir: &Path,
        sources_json: &Path,
        disabled_json: &Path,
    ) -> bool {
        let mut inputs: Vec<SystemTime> = Vec::new();

        if let Some(t) = latest_file_mtime(rules_dir) {
            inputs.push(t);
        }
        if let Some(t) = file_mtime(sources_json) {
            inputs.push(t);
        }
        if let Some(t) = file_mtime(disabled_json) {
            inputs.push(t);
        }

        // No source files at all — cache can't be staler than nothing.
        // (Edge case: data dir was wiped while cache survived. We'll
        // still load the cache; if it doesn't match the empty rules
        // dir, the user can re-fetch.)
        let Some(latest_input) = inputs.into_iter().max() else {
            return false;
        };

        latest_input > cache_mtime
    }
}

fn file_mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

/// Recursively find the newest mtime under `dir`. None if the dir is
/// missing or empty.
fn latest_file_mtime(dir: &Path) -> Option<SystemTime> {
    WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| e.metadata().ok().and_then(|m| m.modified().ok()))
        .max()
}
