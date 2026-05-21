use std::path::Path;

use anyhow::Context;
use serde::Deserialize;
use tauri::{AppHandle, Emitter};

// GTI response structure matching /yara_rules attributes format
#[derive(Debug, Deserialize)]
struct GtiResponse {
    data: Vec<GtiRuleItem>,
    #[serde(default)]
    meta: Option<GtiMeta>,
}

#[derive(Debug, Deserialize)]
struct GtiMeta {
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GtiRuleItem {
    id: String,
    attributes: GtiRuleAttributes,
}

#[derive(Debug, Deserialize)]
struct GtiRuleAttributes {
    name: String,
    rule: Option<String>,
}

/// Download all YARA rules from GTI and save them to `rules_dir` (under the `gti` subdirectory).
pub async fn fetch_gti_rules(
    api_key: &str,
    filter: Option<&str>,
    rules_dir: &Path,
    app: AppHandle,
) -> Result<(), anyhow::Error> {
    let client = crate::net::build_client().context("Building reqwest client")?;

    let gti_rules_dir = rules_dir.join("gti");
    
    // Clean rules/gti/ directory to prevent orphaned files
    if gti_rules_dir.exists() {
        let _ = tokio::fs::remove_dir_all(&gti_rules_dir).await;
    }
    tokio::fs::create_dir_all(&gti_rules_dir)
        .await
        .context("Creating gti rules directory")?;

    let mut page_cursor: Option<String> = None;
    let mut rules_loaded: u64 = 0;
    let source = "gti";

    loop {
        let mut req = client
            .get("https://www.virustotal.com/api/v3/yara_rules")
            .header("X-Apikey", api_key)
            .query(&[("limit", "100")]);

        if let Some(f) = filter.filter(|f| !f.trim().is_empty()) {
            req = req.query(&[("filter", f)]);
        }
        if let Some(ref cursor) = page_cursor {
            req = req.query(&[("cursor", cursor.as_str())]);
        }

        let response = req.send().await.context("GET yara_rules failed")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            let err = format!("GTI API error {}: {}", status, body);
            let _ = app.emit(
                "rule-fetch-error",
                serde_json::json!({ "source": source, "error": err }),
            );
            return Err(anyhow::anyhow!("{}", err));
        }

        let gti_resp: GtiResponse = response.json().await.context("Parsing GTI response")?;

        for rule_item in &gti_resp.data {
            let name = sanitise_filename(&rule_item.attributes.name);
            let rules_content = match &rule_item.attributes.rule {
                Some(r) if !r.is_empty() => r.clone(),
                _ => {
                    log::debug!("GTI rule {} has no content, skipping", rule_item.id);
                    continue;
                }
            };

            // Attempt to split rules into individual files.
            // split_yara_rules is synchronous, we run it directly.
            let split = crate::parsers::yaml::split_yara_rules(&rules_content, &gti_rules_dir);
            if split > 0 {
                rules_loaded += split;
                log::debug!("Split {} rules from GTI rule {}", split, name);
            } else {
                // Fallback: write the single rule file as-is
                let file_path = gti_rules_dir.join(format!("gti_{}.yar", name));
                tokio::fs::write(&file_path, &rules_content)
                    .await
                    .with_context(|| format!("Writing {:?}", file_path))?;
                rules_loaded += 1;
                log::debug!("Saved GTI rule: {}", name);
            }

            let _ = app.emit(
                "rule-fetch-progress",
                serde_json::json!({
                    "source": source,
                    "rulesLoaded": rules_loaded,
                    "status": format!("Loaded: {}", name),
                }),
            );
        }

        // Check for next page
        match gti_resp.meta.and_then(|m| m.cursor) {
            Some(cursor) if !cursor.is_empty() => {
                page_cursor = Some(cursor);
            }
            _ => break,
        }
    }

    let _ = app.emit(
        "rule-fetch-complete",
        serde_json::json!({ "source": source, "totalRules": rules_loaded }),
    );

    log::info!("GTI fetch complete: {} rules loaded", rules_loaded);
    Ok(())
}

fn sanitise_filename(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}
