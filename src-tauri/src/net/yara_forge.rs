use std::io::Read;
use std::path::Path;

use anyhow::Context;
use tauri::{AppHandle, Emitter};

use crate::core::state::YaraForgeTier;

/// Download and extract a YARA Forge ruleset package for the given tier.
pub async fn fetch_yara_forge_rules(
    tier: &YaraForgeTier,
    rules_dir: &Path,
    app: &AppHandle,
) -> Result<u64, anyhow::Error> {
    let source = format!("yara_forge_{}", tier.dir_name().trim_start_matches("yara_forge_"));
    let dest_dir = rules_dir.join(tier.dir_name());

    tokio::fs::create_dir_all(&dest_dir)
        .await
        .context("Creating yara_forge rules directory")?;

    let _ = app.emit(
        "rule-fetch-progress",
        serde_json::json!({
            "source": source,
            "rulesLoaded": 0u64,
            "status": format!("Downloading YARA Forge {} rules…", tier.dir_name()),
        }),
    );

    let client = crate::net::build_client().context("Building reqwest client")?;

    let response = client
        .get(tier.download_url())
        .header("User-Agent", "yara-kiosk/0.1")
        .send()
        .await
        .context("Downloading YARA Forge rules")?;

    if !response.status().is_success() {
        let err = format!("Download failed with status {}", response.status());
        let _ = app.emit("rule-fetch-error", serde_json::json!({ "source": source, "error": err }));
        return Err(anyhow::anyhow!("{}", err));
    }

    let zip_bytes = response.bytes().await.context("Reading download response bytes")?;

    let _ = app.emit(
        "rule-fetch-progress",
        serde_json::json!({
            "source": source,
            "rulesLoaded": 0u64,
            "status": format!("Downloaded {} bytes, extracting…", zip_bytes.len()),
        }),
    );

    let dest_dir_clone = dest_dir.clone();
    let app_clone = app.clone();
    let source_clone = source.clone();
    let zip_bytes_vec = zip_bytes.to_vec();

    let rules_loaded = tokio::task::spawn_blocking(move || {
        extract_zip(&zip_bytes_vec, &dest_dir_clone, &source_clone, &app_clone)
    })
    .await
    .context("spawn_blocking for zip extraction failed")??;

    let _ = app.emit(
        "rule-fetch-complete",
        serde_json::json!({ "source": source, "totalRules": rules_loaded }),
    );

    log::info!("YARA Forge {} fetch complete: {} file(s) extracted", tier.dir_name(), rules_loaded);
    Ok(rules_loaded)
}

fn extract_zip(
    zip_bytes: &[u8],
    dest_dir: &Path,
    source: &str,
    app: &AppHandle,
) -> Result<u64, anyhow::Error> {
    let cursor = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(cursor).context("Parsing downloaded ZIP")?;
    let mut rules_loaded: u64 = 0;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).context("Reading ZIP entry")?;
        let name = entry.name().to_string();

        let ext = Path::new(&name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        if !matches!(ext.as_str(), "yar" | "yara") {
            continue;
        }

        let file_name = Path::new(&name)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown.yar")
            .to_string();

        let mut raw = Vec::new();
        entry.read_to_end(&mut raw).context("Reading ZIP entry bytes")?;

        // Split monolithic file into individual rule files.
        let content_str = String::from_utf8_lossy(&raw);
        let split = crate::parsers::yaml::split_yara_rules(&content_str, dest_dir);

        if split > 0 {
            rules_loaded += split;
            log::debug!("Split {} rules from {}", split, name);
        } else {
            // Fallback: write the monolithic file as-is.
            let dest_path = dest_dir.join(&file_name);
            std::fs::write(&dest_path, &raw)
                .with_context(|| format!("Writing {:?}", dest_path))?;
            rules_loaded += 1;
            log::debug!("Extracted YARA Forge rule file (unsplit): {}", name);
        }

        let _ = app.emit(
            "rule-fetch-progress",
            serde_json::json!({
                "source": source,
                "rulesLoaded": rules_loaded,
                "status": format!("Processed: {} ({} rules)", file_name, rules_loaded),
            }),
        );
    }

    Ok(rules_loaded)
}
