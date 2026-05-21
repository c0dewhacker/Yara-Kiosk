use std::io::{Read, Write};
use std::path::Path;

use anyhow::Context;
use chrono::Utc;

use crate::parsers::yaml::yaml_to_yara;

// ──────────────────────────────────────────────
// Export
// ──────────────────────────────────────────────

/// Zip all rule files from `rules_dir` into a `.ykpk` archive at `output_path`.
pub fn export_package(rules_dir: &Path, output_path: &Path) -> Result<(), anyhow::Error> {
    let file = std::fs::File::create(output_path)
        .with_context(|| format!("Cannot create package at {:?}", output_path))?;
    let mut zip = zip::ZipWriter::new(file);

    let options = zip::write::FileOptions::<()>::default()
        .compression_method(zip::CompressionMethod::Deflated);

    let mut file_paths: Vec<std::path::PathBuf> = Vec::new();
    collect_rule_files(rules_dir, &mut file_paths);

    for abs_path in &file_paths {
        // Store with path relative to rules_dir.
        let rel = abs_path
            .strip_prefix(rules_dir)
            .unwrap_or(abs_path)
            .to_string_lossy()
            .to_string();

        zip.start_file(rel, options.clone())
            .context("Failed to start ZIP entry")?;

        let bytes = std::fs::read(abs_path)
            .with_context(|| format!("Reading {:?}", abs_path))?;
        zip.write_all(&bytes).context("Writing bytes to ZIP")?;
    }

    // Manifest.
    let manifest = serde_json::json!({
        "version": "1",
        "exported_at": Utc::now().to_rfc3339(),
        "file_count": file_paths.len(),
    });
    zip.start_file("manifest.json", options)
        .context("Failed to start manifest entry")?;
    zip.write_all(manifest.to_string().as_bytes())
        .context("Writing manifest")?;

    zip.finish().context("Finalising ZIP archive")?;
    log::info!(
        "Exported {} rule file(s) to {:?}",
        file_paths.len(),
        output_path
    );
    Ok(())
}

fn collect_rule_files(dir: &Path, acc: &mut Vec<std::path::PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rule_files(&path, acc);
        } else if path.is_file() {
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            if matches!(ext.as_str(), "yar" | "yara" | "yaml" | "yml") {
                acc.push(path);
            }
        }
    }
}

// ──────────────────────────────────────────────
// Import
// ──────────────────────────────────────────────

/// Extract a `.ykpk` archive into `rules_dir`, validate each file, and return
/// the number of rule files extracted.
pub fn import_package(package_path: &Path, rules_dir: &Path) -> Result<u64, anyhow::Error> {
    let file = std::fs::File::open(package_path)
        .with_context(|| format!("Cannot open package {:?}", package_path))?;
    let mut zip = zip::ZipArchive::new(file).context("Not a valid ZIP/ykpk file")?;

    let mut extracted: u64 = 0;

    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).context("Failed to read ZIP entry")?;
        let name = entry.name().to_string();

        // Skip manifest.
        if name == "manifest.json" {
            continue;
        }

        let ext = Path::new(&name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        if !matches!(ext.as_str(), "yar" | "yara" | "yaml" | "yml") {
            log::debug!("Skipping non-rule entry in package: {}", name);
            continue;
        }

        // Read content.
        let mut content = String::new();
        entry
            .read_to_string(&mut content)
            .context("Reading ZIP entry")?;

        // Validate.
        if !validate_rule_content(&ext, &content) {
            log::warn!("Skipping invalid rule file in package: {}", name);
            continue;
        }

        // Sanitise path to prevent directory traversal.
        let safe_name = sanitise_zip_path(&name);
        let dest = rules_dir.join(&safe_name);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Creating directory {:?}", parent))?;
        }

        std::fs::write(&dest, &content)
            .with_context(|| format!("Writing extracted file {:?}", dest))?;

        log::debug!("Extracted: {}", name);
        extracted += 1;
    }

    log::info!(
        "Imported {} rule file(s) from {:?}",
        extracted,
        package_path
    );
    Ok(extracted)
}

/// Returns true if the rule content appears valid.
fn validate_rule_content(ext: &str, content: &str) -> bool {
    match ext {
        "yaml" | "yml" => yaml_to_yara(content)
            .map(|yara_src| {
                // Try compiling the converted YARA.
                let mut compiler = yara_x::Compiler::new();
                compiler.add_source(yara_src.as_bytes()).is_ok()
            })
            .unwrap_or(false),
        "yar" | "yara" => {
            let mut compiler = yara_x::Compiler::new();
            compiler.add_source(content.as_bytes()).is_ok()
        }
        _ => false,
    }
}

/// Remove `..` components to prevent directory traversal.
fn sanitise_zip_path(name: &str) -> String {
    name.split('/')
        .filter(|c| !c.is_empty() && *c != "..")
        .collect::<Vec<_>>()
        .join("/")
}
