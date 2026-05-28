use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use chrono::Utc;
use memmap2::Mmap;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter};
use walkdir::WalkDir;

/// Cap the directory traversal depth so a pathological tree (or symlink farm)
/// can't blow the stack or run for an absurdly long time.
const MAX_WALK_DEPTH: usize = 64;

use crate::core::state::{AppState, HexOffset, ScanMatch, ScanResult, ScanStatus};
use crate::output::report;

// ──────────────────────────────────────────────
// Public entry point
// ──────────────────────────────────────────────

pub async fn start_scan(
    path: String,
    scan_id: String,
    state: Arc<AppState>,
    app: AppHandle,
) -> Result<(), anyhow::Error> {
    let target_path = path.clone();
    let scan_start = Utc::now();

    // ── 1. Collect files ─────────────────────
    let root = PathBuf::from(&path);
    let files = tokio::task::spawn_blocking(move || collect_files(&root))
        .await
        .context("spawn_blocking for collect_files failed")?;

    let total_files = files.len() as u64;

    // ── 2. Store initial ScanResult ──────────
    {
        let mut scans = lock!(state.scans);
        scans.insert(
            scan_id.clone(),
            ScanResult {
                scan_id: scan_id.clone(),
                target_path: target_path.clone(),
                started_at: scan_start,
                completed_at: None,
                status: ScanStatus::Running,
                files_scanned: 0,
                total_files,
                skipped_files: 0,
                errored_files: 0,
                matches: Vec::new(),
                report_path: None,
                error: None,
            },
        );
    }

    // ── 3. Get compiled rules ─────────────────
    let (rules_arc, compiled_count) = {
        let guard = lock!(state.rules);
        let rules = guard.clone();
        let count = lock!(state.rule_stats).total_rules;
        (rules, count)
    };

    let fail_scan = |msg: &str| {
        let err = msg.to_string();
        let mut scans = lock!(state.scans);
        if let Some(s) = scans.get_mut(&scan_id) {
            s.status = ScanStatus::Error;
            s.error = Some(err.clone());
            s.completed_at = Some(Utc::now());
        }
        drop(scans);
        let _ = app.emit("scan-error", serde_json::json!({ "scanId": scan_id, "error": err }));
    };

    let rules = match rules_arc {
        None => {
            fail_scan("No rules loaded. Fetch rules from the Rule Manager before scanning.");
            return Err(anyhow::anyhow!("No rules loaded"));
        }
        Some(_) if compiled_count == 0 => {
            fail_scan("No rule files were compiled. Go to Rule Manager → Sources and click FETCH on a source first.");
            return Err(anyhow::anyhow!("0 rules compiled"));
        }
        Some(r) => r,
    };

    // ── 4. Get settings ───────────────────────
    let max_file_size_bytes: u64 = {
        let s = lock!(state.settings);
        s.max_file_size_mb * 1024 * 1024
    };

    // ── 5. Get cancel flag ───────────────────
    let cancel_flag: Arc<AtomicBool> = {
        let mut flags = lock!(state.cancel_flags);
        flags
            .entry(scan_id.clone())
            .or_insert_with(|| Arc::new(AtomicBool::new(false)))
            .clone()
    };

    // ── 6. Channel for rayon→async progress ──
    // Tuple: (filesScanned, totalFiles, matchCount, currentFile, matchedRules)
    // matchedRules is the list of rule names that fired on currentFile (empty
    // if none) — gives the live feed the full picture instead of just the
    // first match.
    let (tx, mut rx) =
        tokio::sync::mpsc::channel::<(u64, u64, u64, String, Vec<String>)>(256);

    let matches_acc: Arc<Mutex<Vec<ScanMatch>>> = Arc::new(Mutex::new(Vec::new()));
    let files_scanned_counter = Arc::new(AtomicU64::new(0));
    let match_counter = Arc::new(AtomicU64::new(0));
    let skipped_counter = Arc::new(AtomicU64::new(0));
    let errored_counter = Arc::new(AtomicU64::new(0));

    let files_for_rayon = files.clone();
    let matches_acc_clone = matches_acc.clone();
    let files_scanned_clone = files_scanned_counter.clone();
    let match_counter_clone = match_counter.clone();
    let skipped_clone = skipped_counter.clone();
    let errored_clone = errored_counter.clone();
    let cancel_flag_rayon = cancel_flag.clone();

    // ── 7. Rayon parallel scan ────────────────
    let rayon_handle = tokio::task::spawn_blocking(move || {
        use rayon::prelude::*;

        files_for_rayon.par_iter().for_each(|file_path| {
            if cancel_flag_rayon.load(Ordering::Relaxed) {
                return;
            }

            // Skip oversized files.
            let file_size = std::fs::metadata(file_path)
                .map(|m| m.len())
                .unwrap_or(0);
            if file_size > max_file_size_bytes {
                skipped_clone.fetch_add(1, Ordering::Relaxed);
                let scanned = files_scanned_clone.fetch_add(1, Ordering::Relaxed) + 1;
                let _ = tx.blocking_send((
                    scanned,
                    total_files,
                    match_counter_clone.load(Ordering::Relaxed),
                    file_path.display().to_string(),
                    Vec::new(),
                ));
                return;
            }

            match scan_file_with_rules(file_path, &rules) {
                Ok(file_matches) => {
                    let new_matches = file_matches.len() as u64;
                    let matched_rules: Vec<String> = file_matches
                        .iter()
                        .map(|m| m.rule_name.clone())
                        .collect();
                    if new_matches > 0 {
                        lock!(matches_acc_clone).extend(file_matches);
                    }
                    let scanned = files_scanned_clone.fetch_add(1, Ordering::Relaxed) + 1;
                    let total_matches =
                        match_counter_clone.fetch_add(new_matches, Ordering::Relaxed) + new_matches;
                    let _ = tx.blocking_send((
                        scanned,
                        total_files,
                        total_matches,
                        file_path.display().to_string(),
                        matched_rules,
                    ));
                }
                Err(e) => {
                    log::warn!("Scan error for {:?}: {}", file_path, e);
                    errored_clone.fetch_add(1, Ordering::Relaxed);
                    let scanned = files_scanned_clone.fetch_add(1, Ordering::Relaxed) + 1;
                    let _ = tx.blocking_send((
                        scanned,
                        total_files,
                        match_counter_clone.load(Ordering::Relaxed),
                        file_path.display().to_string(),
                        Vec::new(),
                    ));
                }
            }
        });
    });

    // ── 8. Forward progress events ────────────
    let app_progress = app.clone();
    let scan_id_progress = scan_id.clone();
    let progress_handle = tokio::spawn(async move {
        while let Some((files_scanned, total, match_count, current_file, matched_rules)) = rx.recv().await {
            let _ = app_progress.emit(
                "scan-progress",
                serde_json::json!({
                    "scanId": scan_id_progress,
                    "filesScanned": files_scanned,
                    "totalFiles": total,
                    "matchCount": match_count,
                    "currentFile": current_file,
                    "matchedRules": matched_rules,
                }),
            );
        }
    });

    // Wait for rayon (sender side) to complete, which closes the channel.
    let _ = rayon_handle.await;
    // Wait for all progress events to flush.
    let _ = progress_handle.await;

    // ── 9. Determine final status ─────────────
    let was_cancelled = cancel_flag.load(Ordering::Relaxed);
    let final_status = if was_cancelled {
        ScanStatus::Cancelled
    } else {
        ScanStatus::Complete
    };

    let all_matches: Vec<ScanMatch> = lock!(matches_acc).drain(..).collect();
    let total_scanned = files_scanned_counter.load(Ordering::Relaxed);
    let total_matches = all_matches.len() as u64;
    let total_skipped = skipped_counter.load(Ordering::Relaxed);
    let total_errored = errored_counter.load(Ordering::Relaxed);
    let completed_at = Utc::now();
    let duration_ms = (completed_at - scan_start).num_milliseconds().unsigned_abs();

    // ── 10. Build partial result for report ───
    let partial_result = ScanResult {
        scan_id: scan_id.clone(),
        target_path: target_path.clone(),
        started_at: scan_start,
        completed_at: Some(completed_at),
        status: final_status.clone(),
        files_scanned: total_scanned,
        total_files,
        skipped_files: total_skipped,
        errored_files: total_errored,
        matches: all_matches.clone(),
        report_path: None,
        error: None,
    };

    // ── 11. Generate HTML report ──────────────
    let report_path = if final_status == ScanStatus::Complete {
        match report::generate_report(&partial_result, &state.reports_dir) {
            Ok(p) => Some(p),
            Err(e) => {
                log::error!("Failed to generate report: {}", e);
                None
            }
        }
    } else {
        None
    };

    // ── 12. Persist final result to state ─────
    {
        let mut scans = lock!(state.scans);
        if let Some(s) = scans.get_mut(&scan_id) {
            s.status = final_status.clone();
            s.files_scanned = total_scanned;
            s.skipped_files = total_skipped;
            s.errored_files = total_errored;
            s.matches = all_matches;
            s.completed_at = Some(completed_at);
            s.report_path = report_path.clone();
        }

        // Cap completed scans at 50 to prevent unbounded memory growth.
        const MAX_SCANS: usize = 50;
        if scans.len() > MAX_SCANS {
            let mut completed: Vec<(String, Option<chrono::DateTime<chrono::Utc>>)> = scans
                .iter()
                .filter(|(_, s)| s.status != ScanStatus::Running)
                .map(|(k, s)| (k.clone(), s.completed_at))
                .collect();
            completed.sort_by_key(|(_, t)| *t);
            let excess = scans.len().saturating_sub(MAX_SCANS);
            for (k, _) in completed.iter().take(excess) {
                scans.remove(k);
            }
        }
    }

    // Clean up cancel flag.
    {
        let mut flags = lock!(state.cancel_flags);
        flags.remove(&scan_id);
    }

    // ── 13. Emit completion event ─────────────
    if final_status == ScanStatus::Complete {
        let _ = app.emit(
            "scan-complete",
            serde_json::json!({
                "scanId": scan_id,
                "reportPath": report_path.unwrap_or_default(),
                "matchCount": total_matches,
                "filesScanned": total_scanned,
                "skippedFiles": total_skipped,
                "erroredFiles": total_errored,
                "durationMs": duration_ms,
            }),
        );
    }

    Ok(())
}

// ──────────────────────────────────────────────
// File utilities
// ──────────────────────────────────────────────

/// Recursively collect all regular files under `root`, capping depth and
/// refusing to follow symlinks. WalkDir handles both safely without recursion.
pub fn collect_files(root: &Path) -> Vec<PathBuf> {
    WalkDir::new(root)
        .follow_links(false)
        .max_depth(MAX_WALK_DEPTH)
        .into_iter()
        .filter_map(|res| match res {
            Ok(entry) => Some(entry),
            Err(e) => {
                log::warn!("Walk error: {}", e);
                None
            }
        })
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .collect()
}

/// Memory-map a file for scanning. Returns `None` for zero-byte files (no
/// match possible) and on mmap failure (caller falls back to read).
fn try_mmap(path: &Path) -> Option<Mmap> {
    let file = File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if meta.len() == 0 {
        return None;
    }
    // SAFETY: we don't share the mapping with other processes that might
    // truncate the file concurrently; if they do, accessing past the new EOF
    // raises SIGBUS, which is no worse than std::fs::read panicking on the
    // same race.
    unsafe { Mmap::map(&file) }.ok()
}

/// Scan a single file against compiled YARA-X rules.
///
/// Uses memory-mapped IO so peak RSS stays bounded regardless of file size —
/// previously every rayon worker allocated `min(file_size, max_file_size_mb)`
/// of heap per file, which scaled with both core count and the configured
/// size cap.
pub fn scan_file_with_rules(
    path: &Path,
    rules: &yara_x::Rules,
) -> Result<Vec<ScanMatch>, anyhow::Error> {
    let mmap = try_mmap(path);
    // Fall back to read() for tiny / unmappable files (e.g. empty, special).
    let owned_bytes: Option<Vec<u8>> = if mmap.is_none() {
        match std::fs::read(path) {
            Ok(b) => Some(b),
            Err(e) => return Err(anyhow::Error::new(e).context("Reading file for scanning")),
        }
    } else {
        None
    };
    let bytes: &[u8] = match (&mmap, &owned_bytes) {
        (Some(m), _) => &m[..],
        (None, Some(v)) => &v[..],
        _ => &[][..],
    };

    // Compute SHA-256 hash — streamed over the mmap, no extra allocation.
    let sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    };

    // Create a scanner and scan the mapped bytes.
    let mut scanner = yara_x::Scanner::new(rules);
    let results = scanner.scan(bytes).context("yara-x scan failed")?;

    let mut scan_matches = Vec::new();

    for matching_rule in results.matching_rules() {
        let rule_name = matching_rule.identifier().to_string();
        let namespace = matching_rule.namespace().to_string();

        // Collect metadata key-value pairs.
        let mut metadata: HashMap<String, String> = HashMap::new();
        for meta in matching_rule.metadata() {
            let key = meta.0.to_string();
            let value: String = match meta.1 {
                yara_x::MetaValue::Integer(n) => n.to_string(),
                yara_x::MetaValue::Float(f) => f.to_string(),
                yara_x::MetaValue::Bool(b) => b.to_string(),
                yara_x::MetaValue::String(s) => s.to_owned(),
                yara_x::MetaValue::Bytes(b) => hex::encode(b),
            };
            metadata.insert(key, value);
        }

        // Collect pattern match offsets.
        let mut offsets: Vec<HexOffset> = Vec::new();
        for pattern in matching_rule.patterns() {
            let identifier = pattern.identifier().to_string();
            for m in pattern.matches() {
                let range = m.range();
                let start = range.start;
                let end = range.end.min(bytes.len());
                let hex_dump = if start < bytes.len() {
                    hex::encode(&bytes[start..end])
                } else {
                    String::new()
                };
                offsets.push(HexOffset {
                    identifier: identifier.clone(),
                    offset: start,
                    length: end.saturating_sub(start),
                    hex_dump,
                });
            }
        }

        scan_matches.push(ScanMatch {
            rule_name,
            namespace,
            file_path: path.display().to_string(),
            sha256: sha256.clone(),
            offsets,
            metadata,
        });
    }

    Ok(scan_matches)
}
