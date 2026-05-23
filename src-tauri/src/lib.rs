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
use parsers::yaml::{load_rules_from_sources, load_rules_from_dir};

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

            let handle = app.handle().clone();
            tauri::async_runtime::spawn(crate::core::watcher::watch_mounts(handle));

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::scan_path,
            commands::scan_usb,
            commands::cancel_scan,
            commands::get_scan_result,
            commands::fetch_yara_forge_rules,
            commands::import_rule_package,
            commands::export_rule_package,
            commands::get_rule_stats,
            commands::get_settings,
            commands::save_settings,
            commands::list_reports,
            commands::get_report_html,
            commands::open_report,
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
    let sources = state.sources.lock().unwrap().clone();
    let disabled = state.disabled_rules.lock().unwrap().clone();
    let rules_dir = state.rules_dir.clone();

    let result = tokio::task::spawn_blocking(move || {
        if sources.is_empty() {
            load_rules_from_dir(&rules_dir)
        } else {
            load_rules_from_sources(&sources, &rules_dir, &disabled)
        }
    })
    .await;

    match result {
        Ok(Ok((rules, count))) => {
            *state.rules.lock().unwrap() = Some(Arc::new(rules));
            {
                let mut stats = state.rule_stats.lock().unwrap();
                stats.total_rules = count as u64;
                stats.last_updated = if count > 0 { Some(chrono::Utc::now()) } else { None };
            }
            log::info!("Pre-loaded {} rule file(s)", count);
            let _ = handle.emit("rules-ready", count as u32);
        }
        Ok(Err(e)) => log::info!("Rules not pre-loaded: {}", e),
        Err(e) => log::warn!("Rule compilation task panicked: {}", e),
    }

    // Auto-import any .ykpk packages dropped in the data directory.
    // Each file is imported then deleted — placing a package here (e.g. via USB
    // on a kiosk) is a zero-interaction rule update.
    let pkgs: Vec<_> = std::fs::read_dir(&data_dir)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("ykpk"))
        .collect();

    if pkgs.is_empty() {
        return;
    }

    let mut any_imported = false;
    for entry in &pkgs {
        let pkg = entry.path();
        match crate::parsers::packager::import_package(&pkg, &state.rules_dir) {
            Ok(_) => {
                log::info!("Auto-imported {:?}", pkg);
                let _ = std::fs::remove_file(&pkg);
                any_imported = true;
            }
            Err(e) => log::warn!("Auto-import failed for {:?}: {}", pkg, e),
        }
    }

    if !any_imported {
        return;
    }

    let sources = state.sources.lock().unwrap().clone();
    let disabled = state.disabled_rules.lock().unwrap().clone();
    let rules_dir = state.rules_dir.clone();

    let result = tokio::task::spawn_blocking(move || {
        if sources.is_empty() {
            load_rules_from_dir(&rules_dir)
        } else {
            load_rules_from_sources(&sources, &rules_dir, &disabled)
        }
    })
    .await;

    match result {
        Ok(Ok((rules, count))) => {
            *state.rules.lock().unwrap() = Some(Arc::new(rules));
            {
                let mut stats = state.rule_stats.lock().unwrap();
                stats.total_rules = count as u64;
                stats.last_updated = Some(chrono::Utc::now());
            }
            log::info!("Recompiled after auto-import: {} rule file(s)", count);
            let _ = handle.emit("rules-ready", count as u32);
        }
        Ok(Err(e)) => log::warn!("Recompile after auto-import failed: {}", e),
        Err(e) => log::warn!("Recompile task panicked: {}", e),
    }
}
