use std::collections::HashSet;
use std::path::Path;

use anyhow::Context;
use serde::Deserialize;

use crate::core::state::RuleSourceConfig;

// ──────────────────────────────────────────────
// YAML rule schema
// ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct YamlRuleFile {
    rule: YamlRule,
}

#[derive(Debug, Deserialize)]
struct YamlRule {
    name: String,
    #[serde(default)]
    meta: std::collections::HashMap<String, serde_yaml::Value>,
    #[serde(default)]
    strings: Vec<YamlString>,
    condition: String,
}

#[derive(Debug, Deserialize)]
struct YamlString {
    id: String,
    value: String,
    #[serde(default = "default_string_type")]
    r#type: String,
}

fn default_string_type() -> String {
    "text".to_string()
}

// ──────────────────────────────────────────────
// Conversion
// ──────────────────────────────────────────────

pub fn yaml_to_yara(yaml_content: &str) -> Result<String, anyhow::Error> {
    let doc: YamlRuleFile =
        serde_yaml::from_str(yaml_content).context("Failed to parse YAML rule")?;
    let rule = doc.rule;

    let mut out = String::new();
    out.push_str(&format!("rule {} {{\n", sanitise_identifier(&rule.name)));

    if !rule.meta.is_empty() {
        out.push_str("  meta:\n");
        for (key, val) in &rule.meta {
            out.push_str(&format!("    {} = {}\n", key, yaml_value_to_yara_meta(val)));
        }
    }

    if !rule.strings.is_empty() {
        out.push_str("  strings:\n");
        for s in &rule.strings {
            let id = if s.id.starts_with('$') { s.id.clone() } else { format!("${}", s.id) };
            let definition = match s.r#type.as_str() {
                "hex" => {
                    let trimmed = s.value.trim();
                    if trimmed.starts_with('{') {
                        format!("{} = {}", id, trimmed)
                    } else {
                        format!("{} = {{ {} }}", id, trimmed)
                    }
                }
                "regex" => {
                    let trimmed = s.value.trim();
                    if trimmed.starts_with('/') {
                        format!("{} = {}", id, trimmed)
                    } else {
                        format!("{} = /{}/", id, trimmed)
                    }
                }
                _ => {
                    let escaped = s.value.replace('\\', "\\\\").replace('"', "\\\"");
                    format!("{} = \"{}\"", id, escaped)
                }
            };
            out.push_str(&format!("    {}\n", definition));
        }
    }

    out.push_str("  condition:\n");
    out.push_str(&format!("    {}\n", rule.condition.trim()));
    out.push_str("}\n");

    Ok(out)
}

fn yaml_value_to_yara_meta(val: &serde_yaml::Value) -> String {
    match val {
        serde_yaml::Value::String(s) => {
            format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
        }
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Number(n) => n.to_string(),
        _ => format!("\"{}\"", format!("{:?}", val).replace('"', "\\\"")),
    }
}

/// Sanitise a string for use as a YARA identifier or a filename.
/// `allow_hyphen` adds `-` to the set of permitted characters (needed for filenames).
fn sanitise(name: &str, allow_hyphen: bool) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' || (allow_hyphen && c == '-') { c } else { '_' })
        .collect()
}

fn sanitise_identifier(name: &str) -> String { sanitise(name, false) }

// ──────────────────────────────────────────────
// Rule loading — source-aware (primary entry point)
// ──────────────────────────────────────────────

/// Compile rules from all enabled sources, skipping files in `disabled`.
/// `disabled` contains absolute path strings of rule files to skip.
/// Returns `(compiled_rules, file_count)` — file_count is 0 when no rule files were found.
pub fn load_rules_from_sources(
    sources: &[RuleSourceConfig],
    rules_base: &Path,
    disabled: &HashSet<String>,
) -> Result<(yara_x::Rules, usize), anyhow::Error> {
    let mut compiler = yara_x::Compiler::new();
    let mut count = 0usize;

    for source in sources.iter().filter(|s| s.enabled) {
        let dir = match source.effective_dir(rules_base) {
            Some(d) => d,
            None => continue,
        };
        if dir.exists() {
            load_rules_recursive(&dir, &mut compiler, &mut count, disabled);
        }
    }

    if count == 0 {
        log::warn!("No rule files found across enabled sources");
    } else {
        log::info!("Compiled {} rule file(s) from enabled sources", count);
    }

    Ok((compiler.build(), count))
}

/// Fallback: compile everything in a single directory tree (no source awareness).
/// Returns `(compiled_rules, file_count)`.
pub fn load_rules_from_dir(rules_dir: &Path) -> Result<(yara_x::Rules, usize), anyhow::Error> {
    let mut compiler = yara_x::Compiler::new();
    let mut count = 0usize;
    load_rules_recursive(rules_dir, &mut compiler, &mut count, &HashSet::new());
    if count == 0 {
        log::warn!("No rule files found in {:?}", rules_dir);
    }
    Ok((compiler.build(), count))
}

fn load_rules_recursive(
    dir: &Path,
    compiler: &mut yara_x::Compiler,
    count: &mut usize,
    disabled: &HashSet<String>,
) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => { log::warn!("Cannot read {:?}: {}", dir, e); return; }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            load_rules_recursive(&path, compiler, count, disabled);
            continue;
        }

        if !disabled.is_empty() {
            let abs = match path.canonicalize() {
                Ok(p) => p.to_string_lossy().to_string(),
                Err(_) => path.to_string_lossy().to_string(),
            };
            if disabled.contains(&abs) {
                log::debug!("Skipping disabled rule file: {:?}", path);
                continue;
            }
        }

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        let yara_source = match ext.as_str() {
            "yar" | "yara" => match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(e) => { log::warn!("Failed to read {:?}: {}", path, e); continue; }
            },
            "yaml" | "yml" => {
                let content = match std::fs::read_to_string(&path) {
                    Ok(s) => s,
                    Err(e) => { log::warn!("Failed to read {:?}: {}", path, e); continue; }
                };
                match yaml_to_yara(&content) {
                    Ok(s) => s,
                    Err(e) => { log::warn!("Skipping {:?}: {}", path, e); continue; }
                }
            }
            _ => continue,
        };

        match compiler.add_source(yara_source.as_bytes()) {
            Ok(_) => { *count += 1; log::debug!("Loaded: {:?}", path); }
            Err(e) => { log::warn!("Compile error in {:?}: {:?}", path, e); }
        }
    }
}

// ──────────────────────────────────────────────
// Rule file splitter
// ──────────────────────────────────────────────

/// Splits a monolithic YARA source into individual `.yar` files in `dest_dir`.
/// Returns the number of rule files written. Falls back to 0 on parse failure;
/// callers can then write the original file themselves.
pub fn split_yara_rules(content: &str, dest_dir: &Path) -> u64 {
    let mut count = 0u64;
    let mut imports = String::new();
    let mut rule_lines: Vec<&str> = Vec::new();
    let mut rule_name = String::new();
    let mut brace_depth: i32 = 0;
    let mut in_rule = false;
    let mut in_block_comment = false;
    let mut in_string = false;
    let mut name_counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();

    for line in content.lines() {
        let trimmed = line.trim();

        if !in_rule {
            if in_block_comment {
                if trimmed.contains("*/") { in_block_comment = false; }
                continue;
            }
            if trimmed.starts_with("/*") {
                if !trimmed.contains("*/") { in_block_comment = true; }
                continue;
            }
            if trimmed.starts_with("import ") || trimmed.starts_with("include ") {
                if !imports.is_empty() { imports.push('\n'); }
                imports.push_str(line);
                continue;
            }
            if let Some(name) = parse_rule_header(trimmed) {
                rule_name = name;
                rule_lines.push(line);
                brace_depth = line_brace_delta(line, &mut in_string);
                in_rule = true;
            }
        } else {
            rule_lines.push(line);
            brace_depth += line_brace_delta(line, &mut in_string);

            if brace_depth <= 0 {
                let idx = name_counts.entry(rule_name.clone()).or_insert(0);
                let fname = if *idx == 0 {
                    format!("{}.yar", sanitise_fname(&rule_name))
                } else {
                    format!("{}_{}.yar", sanitise_fname(&rule_name), idx)
                };
                *idx += 1;

                let mut out = String::new();
                if !imports.is_empty() {
                    out.push_str(&imports);
                    out.push_str("\n\n");
                }
                for l in &rule_lines { out.push_str(l); out.push('\n'); }

                if std::fs::write(dest_dir.join(&fname), out.as_bytes()).is_ok() {
                    count += 1;
                }

                rule_lines.clear();
                rule_name.clear();
                brace_depth = 0;
                in_rule = false;
                in_string = false;
            }
        }
    }

    count
}

fn parse_rule_header(line: &str) -> Option<String> {
    let mut s = line;
    for _ in 0..2 {
        for kw in &["private ", "global "] {
            s = s.strip_prefix(kw).map(|r| r.trim_start()).unwrap_or(s);
        }
    }
    let s = s.strip_prefix("rule ")?.trim_start();
    let name: String = s.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
    if name.is_empty() { None } else { Some(name) }
}

/// Counts brace depth delta for one line, respecting string literals and `//` comments.
fn line_brace_delta(line: &str, in_string: &mut bool) -> i32 {
    let mut depth = 0i32;
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if *in_string {
            if c == '\\' && i + 1 < chars.len() { i += 2; continue; }
            if c == '"' { *in_string = false; }
        } else {
            if c == '/' && i + 1 < chars.len() && chars[i + 1] == '/' { break; }
            match c {
                '"' => *in_string = true,
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
        }
        i += 1;
    }
    depth
}

fn sanitise_fname(name: &str) -> String { sanitise(name, true) }

// ──────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yaml_to_yara_basic() {
        let yaml = r#"
rule:
  name: TestRule
  meta:
    description: "Test rule"
  strings:
    - id: $a
      value: "malicious"
      type: text
  condition: "any of them"
"#;
        let yara = yaml_to_yara(yaml).unwrap();
        assert!(yara.contains("rule TestRule"));
        assert!(yara.contains("$a = \"malicious\""));
        assert!(yara.contains("any of them"));
    }

    #[test]
    fn test_yaml_to_yara_hex() {
        let yaml = r#"
rule:
  name: HexRule
  strings:
    - id: $b
      value: "DE AD BE EF"
      type: hex
  condition: "$b"
"#;
        let yara = yaml_to_yara(yaml).unwrap();
        assert!(yara.contains("{ DE AD BE EF }"));
    }
}
