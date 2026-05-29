use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use tauri::{Emitter, Manager};

/// Recover a poisoned mutex by returning ownership of the inner value.
/// Defined once at the crate root so every submodule can use `lock!(mutex)`.
#[macro_export]
macro_rules! lock {
    ($mutex:expr) => {
        $mutex.lock().unwrap_or_else(|e| e.into_inner())
    };
}

pub mod auth;
pub mod commands;
pub mod core;
pub mod net;
pub mod output;
pub mod parsers;

use core::state::{AppSettings, AppState, RuleSourceConfig, default_sources};

pub struct ManagedState(pub Arc<AppState>);

// ──────────────────────────────────────────────
// CLI / injection configuration
// ──────────────────────────────────────────────

pub struct KioskConfig {
    /// Override the data directory (rules, reports, settings).
    /// Set via `--data-dir=/path/to/dir` on the command line.
    pub data_dir: Option<PathBuf>,
    /// Start the window in fullscreen / kiosk mode.
    /// Set via `--fullscreen` or `--kiosk` on the command line.
    pub fullscreen: bool,
}

impl KioskConfig {
    pub fn from_args() -> Self {
        let mut data_dir = None;
        let mut fullscreen = false;
        for arg in std::env::args().skip(1) {
            if let Some(path) = arg.strip_prefix("--data-dir=") {
                data_dir = Some(PathBuf::from(path));
            } else if arg == "--fullscreen" || arg == "--kiosk" {
                fullscreen = true;
            }
        }
        Self { data_dir, fullscreen }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run(config: KioskConfig) {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_opener::init())
        .setup(move |app| {
            env_logger::init();

            // Resolve data directory: --data-dir flag wins, then Tauri default.
            let app_data_dir = if let Some(ref dir) = config.data_dir {
                std::fs::create_dir_all(dir)
                    .expect("Failed to create --data-dir directory");
                dir.clone()
            } else {
                app.path()
                    .app_data_dir()
                    .expect("Failed to resolve app data directory")
            };

            log::info!("Data directory: {:?}", app_data_dir);

            // Apply fullscreen/kiosk mode if requested.
            if config.fullscreen {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.set_fullscreen(true);
                }
            }

            let state = AppState::new(app_data_dir.clone());

            // Load persisted settings.
            let settings_path = app_data_dir.join("settings.json");
            if settings_path.exists() {
                if let Some(saved) = std::fs::read_to_string(&settings_path)
                    .ok()
                    .and_then(|s| serde_json::from_str::<AppSettings>(&s).ok())
                {
                    *state.settings.lock().unwrap() = saved;
                    log::info!("Loaded persisted settings");
                }
            }

            // Load or seed rule sources.
            let sources_path = app_data_dir.join("sources.json");
            let sources: Vec<RuleSourceConfig> = std::fs::read_to_string(&sources_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_else(|| {
                    let defaults = default_sources();
                    if let Ok(json) = serde_json::to_string_pretty(&defaults) {
                        let _ = std::fs::write(&sources_path, json);
                    }
                    log::info!("Seeded default rule sources");
                    defaults
                });
            *state.sources.lock().unwrap() = sources;

            // Load disabled-rule set.
            let disabled_path = app_data_dir.join("disabled_rules.json");
            let disabled: HashSet<String> = std::fs::read_to_string(&disabled_path)
                .ok()
                .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
                .map(|v| v.into_iter().collect())
                .unwrap_or_default();
            *state.disabled_rules.lock().unwrap() = disabled;

            let state_arc = Arc::new(state);
            app.manage(ManagedState(state_arc.clone()));

            // Compile rules off the main thread so the window appears immediately.
            // The frontend listens for "rules-ready" to update the rule count.
            tauri::async_runtime::spawn(compile_rules_background(
                state_arc.clone(),
                app.handle().clone(),
                app_data_dir.clone(),
            ));

            // Prune old reports based on retention settings.
            crate::commands::prune_old_reports(&state_arc);

            // Auto-refresh rule sources that are older than the configured interval.
            tauri::async_runtime::spawn(auto_refresh_stale_sources(
                state_arc.clone(),
                app.handle().clone(),
            ));

            let handle = app.handle().clone();
            tauri::async_runtime::spawn(crate::core::watcher::watch_mounts(handle));

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::scan_path,
            commands::scan_usb,
            commands::cancel_scan,
            commands::get_scan_result,
            commands::import_rule_package,
            commands::export_rule_package,
            commands::get_rule_stats,
            commands::get_settings,
            commands::save_settings,
            commands::list_reports,
            commands::get_report_html,
            commands::open_report,
            commands::delete_report,
            commands::export_report_to_path,
            commands::list_sources,
            commands::add_source,
            commands::remove_source,
            commands::toggle_source,
            commands::fetch_source,
            commands::list_rules,
            commands::toggle_rule,
            commands::delete_rule,
            commands::get_rule_content,
            commands::save_rule_content,
            commands::clone_rule,
            commands::get_data_dir,
            commands::get_app_info,
            commands::get_gti_filter,
            commands::update_gti_filter,
            commands::verify_password,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// ──────────────────────────────────────────────
// Background rule compilation
// ──────────────────────────────────────────────

async fn compile_rules_background(
    state: Arc<AppState>,
    handle: tauri::AppHandle,
    data_dir: PathBuf,
) {
    // Auto-import any .ykpk packages dropped in the data directory
    // FIRST. Each file is imported then deleted — placing a package
    // here (e.g. via USB on a kiosk) is a zero-interaction rule update.
    // Doing this before the cache check means the mtime staleness
    // detector will correctly invalidate the cache if a fresh package
    // landed.
    auto_import_dropped_packages(&state, &data_dir);

    // Fast path: try the on-disk compiled cache. yara-x deserialize is
    // near-instant vs compiling thousands of rules from source on a
    // low-powered kiosk box. Falls through to full compile when the
    // cache is missing, stale, version-mismatched, or corrupt.
    if try_load_from_cache(&state, &handle) {
        return;
    }

    compile_and_emit(&state, &handle).await;
}

/// Scan the data directory for .ykpk packages, import each one, and
/// delete the source file on success.
fn auto_import_dropped_packages(state: &Arc<AppState>, data_dir: &PathBuf) {
    let pkgs: Vec<_> = std::fs::read_dir(data_dir)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("ykpk"))
        .collect();

    for entry in &pkgs {
        let pkg = entry.path();
        match crate::parsers::packager::import_package(&pkg, &state.rules_dir) {
            Ok(_) => {
                log::info!("Auto-imported {:?}", pkg);
                let _ = std::fs::remove_file(&pkg);
            }
            Err(e) => log::warn!("Auto-import failed for {:?}: {}", pkg, e),
        }
    }
}

/// Try to populate `state.rules` from the on-disk compiled cache.
/// Returns `true` on a successful load (caller can skip full compile).
fn try_load_from_cache(state: &Arc<AppState>, handle: &tauri::AppHandle) -> bool {
    let cache = crate::core::rule_cache::RuleCache::new(&state.data_dir);
    let sources_json = state.data_dir.join("sources.json");
    let disabled_json = state.data_dir.join("disabled_rules.json");

    let Some(rules) = cache.try_load(&state.rules_dir, &sources_json, &disabled_json) else {
        return false;
    };

    // We don't store a "file count" in the cache, so re-derive it by
    // walking the rules dir. Fast — just stats every file.
    let file_count = count_rule_files(&state.rules_dir);
    let sources_snapshot: Vec<core::state::RuleSource> = state.sources.lock().unwrap()
        .iter()
        .map(|s| core::state::RuleSource {
            name: s.name.clone(),
            rule_count: s.rule_count,
            fetched_at: s.fetched_at,
        })
        .collect();

    *state.rules.lock().unwrap() = Some(Arc::new(rules));
    {
        let mut stats = state.rule_stats.lock().unwrap();
        stats.total_rules = file_count;
        // last_updated reflects when the cache was written, not now.
        stats.last_updated = std::fs::metadata(&cache.path)
            .ok()
            .and_then(|m| m.modified().ok())
            .map(chrono::DateTime::<chrono::Utc>::from);
        stats.sources = sources_snapshot;
    }

    log::info!("Rules ready from cache ({} file(s))", file_count);
    let _ = handle.emit("rules-ready", file_count as u32);
    true
}

fn count_rule_files(dir: &std::path::Path) -> u64 {
    walkdir::WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            matches!(
                e.path().extension().and_then(|x| x.to_str()).map(str::to_ascii_lowercase).as_deref(),
                Some("yar") | Some("yara") | Some("yaml") | Some("yml")
            )
        })
        .count() as u64
}

/// Run `reload_rules` off the runtime thread and emit `rules-ready` /
/// `rules-compile-error` for the frontend.
async fn compile_and_emit(state: &Arc<AppState>, handle: &tauri::AppHandle) {
    let state_clone = state.clone();
    let result = tokio::task::spawn_blocking(move || crate::commands::reload_rules(&state_clone)).await;

    match result {
        Ok(Ok(count)) => {
            let _ = handle.emit("rules-ready", count as u32);
        }
        Ok(Err(msg)) => {
            let _ = handle.emit("rules-compile-error", serde_json::json!({ "error": msg }));
            let _ = handle.emit("rules-ready", 0u32);
        }
        Err(e) => {
            let msg = format!("Rule compilation task panicked: {}", e);
            log::warn!("{}", msg);
            let _ = handle.emit("rules-compile-error", serde_json::json!({ "error": msg }));
            let _ = handle.emit("rules-ready", 0u32);
        }
    }
}

// ──────────────────────────────────────────────
// Startup: auto-refresh stale rule sources
// ──────────────────────────────────────────────

async fn auto_refresh_stale_sources(state: Arc<AppState>, handle: tauri::AppHandle) {
    let interval_days = lock!(state.settings).rule_refresh_interval_days;
    if interval_days == 0 {
        return;
    }

    let cutoff = chrono::Utc::now() - chrono::Duration::days(interval_days as i64);
    let stale_ids: Vec<String> = {
        let sources = lock!(state.sources);
        sources.iter()
            .filter(|s| s.enabled && s.fetched_at.map(|t| t < cutoff).unwrap_or(true))
            .map(|s| s.id.clone())
            .collect()
    };

    if stale_ids.is_empty() {
        return;
    }

    // Delay so the UI is interactive before we kick off potentially large
    // HTTP downloads (YARA Forge zips can be hundreds of MB on a metered
    // connection). A user who doesn't want this can disable the interval
    // in Settings before the timer fires.
    log::info!(
        "Auto-refresh will fetch {} stale source(s) in 30s",
        stale_ids.len()
    );
    tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

    for id in &stale_ids {
        log::info!("Auto-refreshing stale rule source: {}", id);
        if let Err(e) = crate::commands::do_fetch_source(id, &state, &handle).await {
            log::warn!("Auto-refresh failed for source {}: {}", id, e);
        }
    }
}
