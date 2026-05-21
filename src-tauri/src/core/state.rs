use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────
// Settings
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    pub auto_start_scans: bool,
    pub gti_api_key: Option<String>,
    pub max_file_size_mb: u64,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            auto_start_scans: false,
            gti_api_key: None,
            max_file_size_mb: 100,
        }
    }
}

// ──────────────────────────────────────────────
// Rule source configuration
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum YaraForgeTier {
    Core,
    Extended,
    Full,
}

impl YaraForgeTier {
    pub fn download_url(&self) -> &'static str {
        match self {
            Self::Core => "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip",
            Self::Extended => "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip",
            Self::Full => "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip",
        }
    }

    pub fn dir_name(&self) -> &'static str {
        match self {
            Self::Core     => "yara_forge_core",
            Self::Extended => "yara_forge_extended",
            Self::Full     => "yara_forge_full",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SourceKind {
    #[serde(rename = "yaraForge")]
    YaraForge { tier: YaraForgeTier },
    #[serde(rename = "gti")]
    GoogleThreatIntelligence {
        filter: Option<String>,
    },
    #[serde(rename = "directory")]
    Directory { path: String },
    #[serde(rename = "url")]
    Url { url: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSourceConfig {
    pub id: String,
    pub name: String,
    pub kind: SourceKind,
    pub enabled: bool,
    pub rule_count: u64,
    pub fetched_at: Option<DateTime<Utc>>,
}

impl RuleSourceConfig {
    /// Subdirectory name under `rules_dir` for managed sources. None for external directories.
    pub fn managed_subdir(&self) -> Option<String> {
        match &self.kind {
            SourceKind::YaraForge { tier } => Some(tier.dir_name().to_string()),
            SourceKind::GoogleThreatIntelligence { .. } => Some("gti".to_string()),
            SourceKind::Url { .. }             => Some(format!("url_{}", &self.id[..8])),
            SourceKind::Directory { .. }       => None,
        }
    }

    /// Effective directory to scan for rule files.
    pub fn effective_dir(&self, rules_base: &std::path::Path) -> Option<PathBuf> {
        match &self.kind {
            SourceKind::Directory { path } => Some(PathBuf::from(path)),
            _ => self.managed_subdir().map(|d| rules_base.join(d)),
        }
    }
}

pub fn default_sources() -> Vec<RuleSourceConfig> {
    vec![
        RuleSourceConfig {
            id: "yara-forge-core".to_string(),
            name: "YARA Forge (Core)".to_string(),
            kind: SourceKind::YaraForge { tier: YaraForgeTier::Core },
            enabled: true,
            rule_count: 0,
            fetched_at: None,
        },
        RuleSourceConfig {
            id: "gti".to_string(),
            name: "Google Threat Intelligence".to_string(),
            kind: SourceKind::GoogleThreatIntelligence { filter: None },
            enabled: true,
            rule_count: 0,
            fetched_at: None,
        },
    ]
}

// ──────────────────────────────────────────────
// Rule file (individual .yar/.yaml file entry)
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleFile {
    pub path: String,
    pub source_id: String,
    pub source_name: String,
    pub name: String,
    pub enabled: bool,
    pub size_bytes: u64,
    pub modified_at: Option<DateTime<Utc>>,
}

// ──────────────────────────────────────────────
// Scan types
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HexOffset {
    pub identifier: String,
    pub offset: usize,
    pub length: usize,
    pub hex_dump: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanMatch {
    pub rule_name: String,
    pub namespace: String,
    pub file_path: String,
    pub sha256: String,
    pub offsets: Vec<HexOffset>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Running,
    Complete,
    Error,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    pub scan_id: String,
    pub target_path: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: ScanStatus,
    pub files_scanned: u64,
    pub total_files: u64,
    pub matches: Vec<ScanMatch>,
    pub report_path: Option<String>,
    pub error: Option<String>,
}

// ──────────────────────────────────────────────
// Rule stats (display aggregate for the header)
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSource {
    pub name: String,
    pub rule_count: u64,
    pub fetched_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleStats {
    pub total_rules: u64,
    pub sources: Vec<RuleSource>,
    pub last_updated: Option<DateTime<Utc>>,
}

impl Default for RuleStats {
    fn default() -> Self {
        Self { total_rules: 0, sources: Vec::new(), last_updated: None }
    }
}

// ──────────────────────────────────────────────
// Reports
// ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportEntry {
    pub scan_id: String,
    pub target_path: String,
    pub created_at: DateTime<Utc>,
    pub match_count: u64,
    pub report_path: String,
}

// ──────────────────────────────────────────────
// Application state
// ──────────────────────────────────────────────

pub struct AppState {
    pub settings: Mutex<AppSettings>,
    pub scans: Mutex<HashMap<String, ScanResult>>,
    pub rules: Mutex<Option<Arc<yara_x::Rules>>>,
    pub rule_stats: Mutex<RuleStats>,
    pub sources: Mutex<Vec<RuleSourceConfig>>,
    pub disabled_rules: Mutex<HashSet<String>>,
    pub rules_dir: PathBuf,
    pub reports_dir: PathBuf,
    pub data_dir: PathBuf,
    pub cancel_flags: Mutex<HashMap<String, Arc<AtomicBool>>>,
}

impl AppState {
    pub fn new(app_data_dir: PathBuf) -> Self {
        let rules_dir = app_data_dir.join("rules");
        let reports_dir = app_data_dir.join("reports");

        std::fs::create_dir_all(&rules_dir).expect("Failed to create rules directory");
        std::fs::create_dir_all(&reports_dir).expect("Failed to create reports directory");

        Self {
            settings: Mutex::new(AppSettings::default()),
            scans: Mutex::new(HashMap::new()),
            rules: Mutex::new(None),
            rule_stats: Mutex::new(RuleStats::default()),
            sources: Mutex::new(Vec::new()),
            disabled_rules: Mutex::new(HashSet::new()),
            rules_dir,
            reports_dir,
            data_dir: app_data_dir,
            cancel_flags: Mutex::new(HashMap::new()),
        }
    }
}
