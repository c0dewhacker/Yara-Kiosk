use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use chrono::Utc;
use tauri::{AppHandle, Emitter, State};
use uuid::Uuid;

use crate::core::state::{
    AppSettings, AppState, ReportEntry, RuleFile, RuleSource, RuleSourceConfig, RuleStats,
    ScanResult, ScanStatus, SourceKind, YaraForgeTier,
};
use crate::parsers::yaml::{load_rules_from_sources, load_rules_from_dir};
use crate::ManagedState;

/// Tracks the yara-x dependency declared in Cargo.toml — surfaced in the
/// Settings About panel. Update both when bumping the crate.
const YARA_X_VERSION: &str = "1.16";


/// Canonicalize `path` and verify it is within `base`.
/// Returns `Err` if the path is non-existent, non-canonical, or outside `base`.
fn validate_path(path: &str, base: &std::path::Path) -> Result<std::path::PathBuf, String> {
    let canonical = std::path::Path::new(path)
        .canonicalize()
        .map_err(|_| "Invalid or non-existent path".to_string())?;
    if !canonical.starts_with(base) {
        return Err("Path is outside the allowed directory".to_string());
    }
    Ok(canonical)
}

// ──────────────────────────────────────────────
// Persistence helpers
// ──────────────────────────────────────────────

fn sources_path(state: &AppState) -> std::path::PathBuf {
    state.data_dir.join("sources.json")
}

fn disabled_path(state: &AppState) -> std::path::PathBuf {
    state.data_dir.join("disabled_rules.json")
}

pub fn save_sources(state: &AppState) {
    let sources = lock!(state.sources).clone();
    if let Ok(json) = serde_json::to_string_pretty(&sources) {
        let _ = std::fs::write(sources_path(state), json);
    }
}

pub fn save_disabled(state: &AppState) {
    let disabled = lock!(state.disabled_rules).clone();
    let list: Vec<String> = disabled.into_iter().collect();
    if let Ok(json) = serde_json::to_string_pretty(&list) {
        let _ = std::fs::write(disabled_path(state), json);
    }
}

// ──────────────────────────────────────────────
// Rule reload
// ──────────────────────────────────────────────

pub fn reload_rules(state: &Arc<AppState>) {
    let sources = lock!(state.sources).clone();
    let disabled = lock!(state.disabled_rules).clone();

    let result = if sources.is_empty() {
        load_rules_from_dir(&state.rules_dir)
    } else {
        load_rules_from_sources(&sources, &state.rules_dir, &disabled)
    };

    match result {
        Ok((compiled, count)) => {
            *lock!(state.rules) = Some(Arc::new(compiled));
            let mut stats = lock!(state.rule_stats);
            stats.total_rules = count as u64;
            stats.last_updated = Some(Utc::now());
            stats.sources = sources.iter().map(|s| RuleSource {
                name: s.name.clone(),
                rule_count: s.rule_count,
                fetched_at: s.fetched_at,
            }).collect();
            log::info!("Rules reloaded: {} file(s) compiled", count);
        }
        Err(e) => log::error!("Failed to reload rules: {}", e),
    }
}

fn spawn_rules_reload(state: Arc<AppState>, app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio::task::spawn_blocking(move || reload_rules(&state))
            .await
            .ok();
        let _ = app.emit("rules-ready", ());
    });
}

fn count_recursive(dir: &std::path::Path, count: &mut u64) {
    let entries = match std::fs::read_dir(dir) { Ok(e) => e, Err(_) => return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            count_recursive(&path, count);
        } else {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
            if matches!(ext.as_str(), "yar" | "yara" | "yaml" | "yml") {
                *count += 1;
            }
        }
    }
}

fn count_in_dir(dir: &std::path::Path) -> u64 {
    let mut n = 0;
    count_recursive(dir, &mut n);
    n
}

// ──────────────────────────────────────────────
// Scan commands
// ──────────────────────────────────────────────

#[tauri::command]
pub async fn scan_path(
    path: String,
    state: State<'_, ManagedState>,
    app: AppHandle,
) -> Result<String, String> {
    // Item 4: prevent multiple concurrent scans.
    {
        let scans = lock!(state.0.scans);
        if scans.values().any(|s| s.status == ScanStatus::Running) {
            return Err("A scan is already in progress. Wait for it to complete or cancel it first.".to_string());
        }
    }

    let scan_id = Uuid::new_v4().to_string();
    let cancel_flag = Arc::new(AtomicBool::new(false));
    lock!(state.0.cancel_flags).insert(scan_id.clone(), cancel_flag);

    let state_arc = state.0.clone();
    let scan_id_clone = scan_id.clone();
    let app_clone = app.clone();

    tokio::spawn(async move {
        if let Err(e) = crate::core::scanner::start_scan(
            path, scan_id_clone.clone(), state_arc, app_clone.clone(),
        ).await {
            log::error!("Scan {} error: {}", scan_id_clone, e);
            let _ = app_clone.emit(
                "scan-error",
                serde_json::json!({ "scanId": scan_id_clone, "error": e.to_string() }),
            );
        }
    });

    Ok(scan_id)
}

#[tauri::command]
pub async fn scan_usb(
    mount_point: String,
    state: State<'_, ManagedState>,
    app: AppHandle,
) -> Result<String, String> {
    scan_path(mount_point, state, app).await
}

#[tauri::command]
pub fn cancel_scan(scan_id: String, state: State<'_, ManagedState>) -> Result<(), String> {
    let flags = lock!(state.0.cancel_flags);
    if let Some(flag) = flags.get(&scan_id) {
        flag.store(true, Ordering::Relaxed);
    }
    Ok(())
}

#[tauri::command]
pub fn get_scan_result(scan_id: String, state: State<'_, ManagedState>) -> Result<ScanResult, String> {
    lock!(state.0.scans).get(&scan_id).cloned()
        .ok_or_else(|| format!("No scan found with id {}", scan_id))
}

// ──────────────────────────────────────────────
// Rule source commands
// ──────────────────────────────────────────────

#[tauri::command]
pub fn list_sources(state: State<'_, ManagedState>) -> Result<Vec<RuleSourceConfig>, String> {
    Ok(lock!(state.0.sources).clone())
}

#[tauri::command]
pub fn add_source(
    name: String,
    kind: SourceKind,
    state: State<'_, ManagedState>,
) -> Result<RuleSourceConfig, String> {
    let new_source = RuleSourceConfig {
        id: Uuid::new_v4().to_string(),
        name,
        kind,
        enabled: true,
        rule_count: 0,
        fetched_at: None,
    };

    if let Some(subdir) = new_source.managed_subdir() {
        let dir = state.0.rules_dir.join(&subdir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    }

    lock!(state.0.sources).push(new_source.clone());
    save_sources(&state.0);
    Ok(new_source)
}

#[tauri::command]
pub fn remove_source(id: String, state: State<'_, ManagedState>, app: AppHandle) -> Result<(), String> {
    let mut sources = lock!(state.0.sources);
    if let Some(pos) = sources.iter().position(|s| s.id == id) {
        let source = sources.remove(pos);
        drop(sources);

        // Remove managed directory if applicable.
        if let Some(subdir) = source.managed_subdir() {
            let dir = state.0.rules_dir.join(&subdir);
            if dir.exists() {
                let _ = std::fs::remove_dir_all(&dir);
            }
        }

        save_sources(&state.0);
        spawn_rules_reload(state.0.clone(), app);
    }
    Ok(())
}

#[tauri::command]
pub fn toggle_source(
    id: String,
    enabled: bool,
    state: State<'_, ManagedState>,
    app: AppHandle,
) -> Result<(), String> {
    let mut sources = lock!(state.0.sources);
    if let Some(src) = sources.iter_mut().find(|s| s.id == id) {
        src.enabled = enabled;
    }
    drop(sources);
    save_sources(&state.0);
    spawn_rules_reload(state.0.clone(), app);
    Ok(())
}

/// Core fetch logic usable both from the command and startup auto-refresh.
pub async fn do_fetch_source(
    id: &str,
    state: &Arc<AppState>,
    app: &AppHandle,
) -> Result<(), String> {
    let source = {
        let sources = lock!(state.sources);
        sources.iter().find(|s| s.id == id).cloned()
            .ok_or_else(|| format!("Source {} not found", id))?
    };

    match &source.kind {
        SourceKind::YaraForge { tier } => {
            let tier = tier.clone();
            let rules_dir = state.rules_dir.clone();
            crate::net::yara_forge::fetch_yara_forge_rules(&tier, &rules_dir, app)
                .await
                .map_err(|e| e.to_string())?;
        }
        SourceKind::GoogleThreatIntelligence { filter } => {
            let api_key = lock!(state.settings).gti_api_key.clone()
                .ok_or("No Google Threat Intelligence API key configured")?;
            let rules_dir = state.rules_dir.clone();
            crate::net::gti::fetch_gti_rules(&api_key, filter.as_deref(), &rules_dir, app.clone())
                .await
                .map_err(|e| e.to_string())?;
        }
        SourceKind::Url { url } => {
            fetch_url_source(id, url, &state.rules_dir, app)
                .await
                .map_err(|e| e.to_string())?;
        }
        SourceKind::Directory { .. } => {
            // Local directory — no fetch needed; just reload.
        }
    }

    {
        let mut sources = lock!(state.sources);
        if let Some(src) = sources.iter_mut().find(|s| s.id == id) {
            src.fetched_at = Some(Utc::now());
            if let Some(dir) = src.effective_dir(&state.rules_dir) {
                src.rule_count = count_in_dir(&dir);
            }
        }
    }
    save_sources(state);
    spawn_rules_reload(state.clone(), app.clone());
    Ok(())
}

#[tauri::command]
pub async fn fetch_source(
    id: String,
    state: State<'_, ManagedState>,
    app: AppHandle,
) -> Result<(), String> {
    do_fetch_source(&id, &state.0, &app).await
}

async fn fetch_url_source(
    source_id: &str,
    url: &str,
    rules_base: &std::path::Path,
    app: &AppHandle,
) -> Result<(), anyhow::Error> {
    use anyhow::Context;

    let subdir = rules_base.join(format!("url_{}", &source_id[..8]));
    tokio::fs::create_dir_all(&subdir).await.context("Creating url source dir")?;

    let _ = app.emit("rule-fetch-progress", serde_json::json!({
        "source": source_id, "rulesLoaded": 0u64, "status": format!("Downloading {}", url)
    }));

    let client = crate::net::build_client()?;
    let resp = client.get(url).header("User-Agent", "yara-kiosk/0.1").send().await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("HTTP {}", resp.status()));
    }

    let bytes = resp.bytes().await?;
    let url_lower = url.to_lowercase();

    if url_lower.ends_with(".zip") {
        use std::io::Read;
        let cursor = std::io::Cursor::new(bytes.as_ref());
        let mut archive = zip::ZipArchive::new(cursor).context("Parsing ZIP")?;
        let mut count = 0u64;
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            let name = entry.name().to_string();
            let ext = std::path::Path::new(&name)
                .extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
            if !matches!(ext.as_str(), "yar" | "yara" | "yaml" | "yml") { continue; }
            let file_name = std::path::Path::new(&name)
                .file_name().and_then(|n| n.to_str()).unwrap_or("rule.yar").to_string();
            let mut content = Vec::new();
            entry.read_to_end(&mut content)?;
            std::fs::write(subdir.join(&file_name), &content)?;
            count += 1;
        }
        let _ = app.emit("rule-fetch-complete", serde_json::json!({ "source": source_id, "totalRules": count }));
    } else {
        // Single .yar/.yara file — split into individual rules.
        let content_str = String::from_utf8_lossy(&bytes);
        let split = crate::parsers::yaml::split_yara_rules(&content_str, &subdir);
        if split == 0 {
            // Fallback: write as-is.
            let file_name = url.split('/').next_back().unwrap_or("rules.yar");
            std::fs::write(subdir.join(file_name), &bytes)?;
        }
        let _ = app.emit("rule-fetch-complete", serde_json::json!({ "source": source_id, "totalRules": split.max(1) }));
    }

    Ok(())
}

// ──────────────────────────────────────────────
// Individual rule file commands
// ──────────────────────────────────────────────

#[tauri::command]
pub async fn list_rules(state: State<'_, ManagedState>) -> Result<Vec<RuleFile>, String> {
    let sources = lock!(state.0.sources).clone();
    let disabled = lock!(state.0.disabled_rules).clone();
    let rules_base = state.0.rules_dir.clone();

    tokio::task::spawn_blocking(move || {
        let mut files: Vec<RuleFile> = Vec::new();
        for source in &sources {
            let dir = match source.effective_dir(&rules_base) {
                Some(d) => d,
                None => continue,
            };
            if !dir.exists() { continue; }
            collect_rule_files(&dir, &source, &disabled, &mut files);
        }
        files.sort_by(|a, b| a.name.cmp(&b.name));
        files
    })
    .await
    .map_err(|e| e.to_string())
}

fn collect_rule_files(
    dir: &std::path::Path,
    source: &RuleSourceConfig,
    disabled: &HashSet<String>,
    out: &mut Vec<RuleFile>,
) {
    let entries = match std::fs::read_dir(dir) { Ok(e) => e, Err(_) => return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rule_files(&path, source, disabled, out);
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        if !matches!(ext.as_str(), "yar" | "yara" | "yaml" | "yml") { continue; }

        let abs = path.canonicalize()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| path.to_string_lossy().to_string());

        let meta = std::fs::metadata(&path).ok();
        let size_bytes = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let modified_at = meta.and_then(|m| m.modified().ok())
            .map(chrono::DateTime::<chrono::Utc>::from);

        out.push(RuleFile {
            path: abs.clone(),
            source_id: source.id.clone(),
            source_name: source.name.clone(),
            name: path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string(),
            enabled: !disabled.contains(&abs),
            size_bytes,
            modified_at,
        });
    }
}

#[tauri::command]
pub fn toggle_rule(
    path: String,
    enabled: bool,
    state: State<'_, ManagedState>,
    app: AppHandle,
) -> Result<(), String> {
    // Always store the canonical path so the disabled-set can't drift between
    // canonical and non-canonical forms across calls — a previous fallback
    // here left rules stuck disabled when re-enabling under a different form.
    let canonical = std::path::Path::new(&path)
        .canonicalize()
        .map_err(|e| format!("Cannot resolve rule path {}: {}", path, e))?
        .to_string_lossy()
        .to_string();

    {
        let mut disabled = lock!(state.0.disabled_rules);
        if enabled { disabled.remove(&canonical); } else { disabled.insert(canonical); }
    }
    save_disabled(&state.0);
    spawn_rules_reload(state.0.clone(), app);
    Ok(())
}

#[tauri::command]
pub fn delete_rule(path: String, state: State<'_, ManagedState>, app: AppHandle) -> Result<(), String> {
    let canonical = validate_path(&path, &state.0.rules_dir)?;
    let abs = canonical.to_string_lossy().to_string();
    std::fs::remove_file(&canonical).map_err(|e| e.to_string())?;
    lock!(state.0.disabled_rules).remove(&abs);
    save_disabled(&state.0);
    spawn_rules_reload(state.0.clone(), app);
    Ok(())
}

#[tauri::command]
pub fn get_rule_content(path: String, state: State<'_, ManagedState>) -> Result<String, String> {
    let canonical = validate_path(&path, &state.0.rules_dir)?;
    std::fs::read_to_string(&canonical).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn save_rule_content(
    path: String,
    content: String,
    state: State<'_, ManagedState>,
    app: AppHandle,
) -> Result<(), String> {
    let canonical = validate_path(&path, &state.0.rules_dir)?;
    std::fs::write(&canonical, content.as_bytes()).map_err(|e| e.to_string())?;
    spawn_rules_reload(state.0.clone(), app);
    Ok(())
}

#[tauri::command]
pub fn clone_rule(path: String, state: State<'_, ManagedState>, app: AppHandle) -> Result<RuleFile, String> {
    let src = validate_path(&path, &state.0.rules_dir)?;
    let stem = src.file_stem().and_then(|s| s.to_str()).unwrap_or("rule");
    let ext  = src.extension().and_then(|s| s.to_str()).unwrap_or("yar");
    let dir  = src.parent().ok_or("No parent directory")?;

    // Find an unused filename.
    let mut idx = 1u32;
    let dest = loop {
        let candidate = dir.join(format!("{}_copy{}.{}", stem, if idx == 1 { "".to_string() } else { idx.to_string() }, ext));
        if !candidate.exists() { break candidate; }
        idx += 1;
    };

    std::fs::copy(&src, &dest).map_err(|e| e.to_string())?;

    let abs = dest.canonicalize()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| dest.to_string_lossy().to_string());

    let meta = std::fs::metadata(&dest).ok();
    let size_bytes = meta.as_ref().map(|m| m.len()).unwrap_or(0);
    let modified_at = meta.and_then(|m| m.modified().ok())
        .map(chrono::DateTime::<chrono::Utc>::from);

    // Find the source this file belongs to.
    let sources = lock!(state.0.sources).clone();
    let (source_id, source_name) = sources.iter()
        .find(|s| s.effective_dir(&state.0.rules_dir)
            .map(|d| abs.starts_with(&d.to_string_lossy().to_string()))
            .unwrap_or(false))
        .map(|s| (s.id.clone(), s.name.clone()))
        .unwrap_or_else(|| ("unknown".to_string(), "Unknown".to_string()));

    spawn_rules_reload(state.0.clone(), app);

    Ok(RuleFile {
        path: abs,
        source_id,
        source_name,
        name: dest.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string(),
        enabled: true,
        size_bytes,
        modified_at,
    })
}

// ──────────────────────────────────────────────
// Legacy fetch commands (kept for compatibility)
// ──────────────────────────────────────────────

#[tauri::command]
pub async fn fetch_yara_forge_rules(
    state: State<'_, ManagedState>,
    app: AppHandle,
) -> Result<(), String> {
    let rules_dir = state.0.rules_dir.clone();
    crate::net::yara_forge::fetch_yara_forge_rules(
        &YaraForgeTier::Core,
        &rules_dir,
        &app,
    )
    .await
    .map_err(|e| e.to_string())?;
    spawn_rules_reload(state.0.clone(), app);
    Ok(())
}

// ──────────────────────────────────────────────
// Rule package commands
// ──────────────────────────────────────────────

#[tauri::command]
pub async fn import_rule_package(
    package_path: String,
    state: State<'_, ManagedState>,
    app: AppHandle,
) -> Result<(), String> {
    let pkg_path = std::path::PathBuf::from(&package_path);
    let rules_dir = state.0.rules_dir.clone();
    tokio::task::spawn_blocking(move || {
        crate::parsers::packager::import_package(&pkg_path, &rules_dir)
    })
    .await.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?;
    spawn_rules_reload(state.0.clone(), app);
    Ok(())
}

#[tauri::command]
pub async fn export_rule_package(
    output_path: String,
    state: State<'_, ManagedState>,
) -> Result<String, String> {
    let out_path = std::path::PathBuf::from(&output_path);
    let rules_dir = state.0.rules_dir.clone();
    tokio::task::spawn_blocking(move || {
        crate::parsers::packager::export_package(&rules_dir, &out_path)
    })
    .await.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?;
    Ok(output_path)
}

#[tauri::command]
pub fn get_rule_stats(state: State<'_, ManagedState>) -> Result<RuleStats, String> {
    Ok(lock!(state.0.rule_stats).clone())
}

// ──────────────────────────────────────────────
// Settings commands
// ──────────────────────────────────────────────

#[tauri::command]
pub fn get_settings(state: State<'_, ManagedState>) -> Result<AppSettings, String> {
    Ok(lock!(state.0.settings).clone())
}

#[tauri::command]
pub async fn save_settings(
    settings: AppSettings,
    state: State<'_, ManagedState>,
) -> Result<(), String> {
    // Persist to disk first via temp-and-rename so a write failure can't
    // leave in-memory and on-disk state diverged.
    let settings_path = state.0.data_dir.join("settings.json");
    let tmp_path = state.0.data_dir.join("settings.json.tmp");
    let json = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    tokio::fs::write(&tmp_path, json).await.map_err(|e| e.to_string())?;
    tokio::fs::rename(&tmp_path, &settings_path)
        .await
        .map_err(|e| e.to_string())?;
    *lock!(state.0.settings) = settings;
    Ok(())
}

#[tauri::command]
pub fn get_data_dir(state: State<'_, ManagedState>) -> Result<String, String> {
    Ok(state.0.data_dir.display().to_string())
}

#[tauri::command]
pub async fn verify_password(password: String) -> Result<bool, String> {
    tokio::task::spawn_blocking(move || crate::auth::verify_system_password(&password))
        .await
        .map_err(|e| e.to_string())?
}

// ──────────────────────────────────────────────
// Report commands
// ──────────────────────────────────────────────

#[tauri::command]
pub async fn list_reports(state: State<'_, ManagedState>) -> Result<Vec<ReportEntry>, String> {
    let reports_dir = state.0.reports_dir.clone();
    let entries = tokio::task::spawn_blocking(move || -> Result<Vec<ReportEntry>, anyhow::Error> {
        let mut result = Vec::new();
        let dir_entries = match std::fs::read_dir(&reports_dir) { Ok(e) => e, Err(_) => return Ok(result) };
        for entry in dir_entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("html") { continue; }
            let meta = std::fs::metadata(&path).ok();
            let created_at = meta.and_then(|m| m.modified().ok())
                .map(chrono::DateTime::<chrono::Utc>::from)
                .unwrap_or_else(chrono::Utc::now);
            let (scan_id, target_path, match_count) = extract_report_meta(&path);
            result.push(ReportEntry { scan_id, target_path, created_at, match_count, report_path: path.display().to_string() });
        }
        result.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(result)
    }).await.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?;
    Ok(entries)
}

/// Return the raw HTML of a report file for in-app display.
#[tauri::command]
pub fn get_report_html(path: String, state: State<'_, ManagedState>) -> Result<String, String> {
    let canonical = validate_path(&path, &state.0.reports_dir)?;
    std::fs::read_to_string(&canonical).map_err(|e| e.to_string())
}

/// Delete a report HTML file from disk.
#[tauri::command]
pub fn delete_report(path: String, state: State<'_, ManagedState>) -> Result<(), String> {
    let canonical = validate_path(&path, &state.0.reports_dir)?;
    std::fs::remove_file(&canonical).map_err(|e| e.to_string())
}

/// Copy a report file to a user-chosen destination (e.g. a USB drive).
#[tauri::command]
pub async fn export_report_to_path(
    report_path: String,
    dest_path: String,
    state: State<'_, ManagedState>,
) -> Result<(), String> {
    let canonical = validate_path(&report_path, &state.0.reports_dir)?;
    if let Some(parent) = std::path::Path::new(&dest_path).parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| e.to_string())?;
    }
    tokio::fs::copy(&canonical, &dest_path).await.map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn open_report(
    report_path: String,
    app: AppHandle,
    state: State<'_, ManagedState>,
) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    let canonical = validate_path(&report_path, &state.0.reports_dir)?;
    app.opener()
        .open_path(canonical.to_str().ok_or("Invalid UTF-8 in path")?, None::<&str>)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Delete all report HTML files older than the configured retention period.
pub fn prune_old_reports(state: &AppState) {
    let retention_days = lock!(state.settings).report_retention_days;
    if retention_days == 0 {
        return;
    }
    let cutoff = Utc::now() - chrono::Duration::days(retention_days as i64);
    let entries = match std::fs::read_dir(&state.reports_dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let modified = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .map(chrono::DateTime::<Utc>::from)
            .unwrap_or(Utc::now());
        if modified < cutoff {
            if let Err(e) = std::fs::remove_file(&path) {
                log::warn!("Failed to prune report {:?}: {}", path, e);
            } else {
                log::info!("Pruned old report: {:?}", path);
            }
        }
    }
}

/// Update the GTI source's filter string and persist.
#[tauri::command]
pub fn update_gti_filter(filter: Option<String>, state: State<'_, ManagedState>) -> Result<(), String> {
    let mut sources = lock!(state.0.sources);
    if let Some(src) = sources.iter_mut().find(|s| matches!(s.kind, SourceKind::GoogleThreatIntelligence { .. })) {
        src.kind = SourceKind::GoogleThreatIntelligence { filter };
    }
    drop(sources);
    save_sources(&state.0);
    Ok(())
}

/// Return the GTI source's current filter string (if any).
#[tauri::command]
pub fn get_gti_filter(state: State<'_, ManagedState>) -> Result<Option<String>, String> {
    let sources = lock!(state.0.sources);
    let filter = sources.iter()
        .find_map(|s| {
            if let SourceKind::GoogleThreatIntelligence { filter } = &s.kind {
                Some(filter.clone())
            } else {
                None
            }
        })
        .flatten();
    Ok(filter)
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub version: String,
    pub yara_x_version: &'static str,
}

/// Return version information for display in the Settings About section.
#[tauri::command]
pub fn get_app_info(app: AppHandle) -> Result<AppInfo, String> {
    Ok(AppInfo {
        version: app.package_info().version.to_string(),
        yara_x_version: YARA_X_VERSION,
    })
}

/// Parse the `<script id="scan-meta">` JSON block embedded in each report.
/// Returns `(scan_id, target_path, match_count)`.
fn extract_report_meta(path: &std::path::Path) -> (String, String, u64) {
    let fallback_scan_id = || {
        path.file_stem()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .splitn(3, '_')
            .nth(1)
            .unwrap_or("unknown")
            .to_string()
    };

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return (fallback_scan_id(), String::new(), 0),
    };

    for line in content.lines() {
        if line.contains("id=\"scan-meta\"") {
            if let (Some(s), Some(e)) = (line.find('>'), line.rfind('<')) {
                if s < e {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line[s + 1..e]) {
                        let scan_id = v["scanId"].as_str().unwrap_or("unknown").to_string();
                        let target = v["target"].as_str().unwrap_or("").to_string();
                        let match_count = v["matchCount"].as_u64().unwrap_or(0);
                        return (scan_id, target, match_count);
                    }
                }
            }
        }
    }

    (fallback_scan_id(), String::new(), 0)
}
