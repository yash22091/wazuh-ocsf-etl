use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::warn;

// ─── Constants ────────────────────────────────────────────────────────────────

pub(crate) const DEFAULT_ALERTS_FILE: &str       = "/var/ossec/logs/alerts/alerts.json";
pub(crate) const DEFAULT_MAPPINGS_FILE: &str     = "config/field_mappings.toml";
pub(crate) const DEFAULT_STATE_FILE: &str        = "state/alerts.pos";
pub(crate) const CONFIG_POLL_SECS: u64           = 10;
pub(crate) const DEFAULT_BATCH_SIZE: usize       = 5_000;
pub(crate) const DEFAULT_FLUSH_INTERVAL_SECS: u64 = 5;
pub(crate) const DEFAULT_CHANNEL_CAP: usize      = 50_000;

// ─── App config ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum InputMode {
    File,
    ZeroMq,
}

pub(crate) struct AppConfig {
    pub(crate) clickhouse_url:           String,
    pub(crate) clickhouse_db:            String,
    pub(crate) clickhouse_user:          String,
    pub(crate) clickhouse_password:      String,
    pub(crate) alerts_file:              String,
    pub(crate) mappings_file:            PathBuf,
    pub(crate) state_file:               PathBuf,
    pub(crate) special_locations:        Vec<String>,
    pub(crate) data_ttl_days:            Option<u32>,
    pub(crate) seek_to_end_on_first_run: bool,
    pub(crate) batch_size:               usize,
    pub(crate) flush_interval_secs:      u64,
    pub(crate) channel_cap:              usize,
    pub(crate) input_mode:               InputMode,
    pub(crate) zeromq_uri:               String,
    pub(crate) unmapped_fields_file:     PathBuf,
    /// When false the raw_data column is stored as an empty string.
    /// Saves significant storage (raw JSON can be 2-20 KB per event).
    pub(crate) store_raw_data:           bool,
}

impl AppConfig {
    pub(crate) fn from_env() -> Self {
        let _ = dotenvy::dotenv();
        let special_locations: Vec<String> = std::env::var("SPECIAL_LOCATIONS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Self {
            clickhouse_url: std::env::var("CLICKHOUSE_URL")
                .unwrap_or_else(|_| "http://localhost:8123".into()),
            clickhouse_db: std::env::var("CLICKHOUSE_DATABASE")
                .unwrap_or_else(|_| "wazuh_ocsf".into()),
            clickhouse_user: std::env::var("CLICKHOUSE_USER")
                .unwrap_or_else(|_| "default".into()),
            clickhouse_password: std::env::var("CLICKHOUSE_PASSWORD")
                .unwrap_or_default(),
            alerts_file: std::env::var("ALERTS_FILE")
                .unwrap_or_else(|_| DEFAULT_ALERTS_FILE.into()),
            mappings_file: PathBuf::from(
                std::env::var("FIELD_MAPPINGS_FILE")
                    .unwrap_or_else(|_| DEFAULT_MAPPINGS_FILE.into()),
            ),
            state_file: PathBuf::from(
                std::env::var("STATE_FILE")
                    .unwrap_or_else(|_| DEFAULT_STATE_FILE.into()),
            ),
            special_locations,
            data_ttl_days: std::env::var("DATA_TTL_DAYS").ok().and_then(|s| {
                s.trim().parse::<u32>().map_err(|e| {
                    warn!("DATA_TTL_DAYS={s:?} is not a valid integer ({e}) — TTL disabled");
                }).ok()
            }),
            seek_to_end_on_first_run: std::env::var("SEEK_TO_END_ON_FIRST_RUN")
                .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no"))
                .unwrap_or(true),
            batch_size: parse_env_usize("BATCH_SIZE", DEFAULT_BATCH_SIZE),
            flush_interval_secs: parse_env_u64("FLUSH_INTERVAL_SECS", DEFAULT_FLUSH_INTERVAL_SECS),
            channel_cap: parse_env_usize("CHANNEL_CAP", DEFAULT_CHANNEL_CAP),
            input_mode: match std::env::var("INPUT_MODE")
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
                .as_str()
            {
                "zeromq" | "zmq" | "0mq" => InputMode::ZeroMq,
                _ => InputMode::File,
            },
            zeromq_uri: std::env::var("ZEROMQ_URI")
                .unwrap_or_else(|_| "tcp://localhost:11111".into()),
            unmapped_fields_file: PathBuf::from(
                std::env::var("UNMAPPED_FIELDS_FILE")
                    .unwrap_or_else(|_| "state/unmapped_fields.json".into()),
            ),
            store_raw_data: std::env::var("STORE_RAW_DATA")
                .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no"))
                .unwrap_or(true),
        }
    }
}

pub(crate) fn parse_env_usize(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Err(_) => default,
        Ok(s) => s.trim().parse::<usize>().unwrap_or_else(|e| {
            warn!("{name}={s:?} is not a valid integer ({e}) — using default {default}");
            default
        }),
    }
}

pub(crate) fn parse_env_u64(name: &str, default: u64) -> u64 {
    match std::env::var(name) {
        Err(_) => default,
        Ok(s) => s.trim().parse::<u64>().unwrap_or_else(|e| {
            warn!("{name}={s:?} is not a valid integer ({e}) — using default {default}");
            default
        }),
    }
}

// ─── Custom mappings (field_mappings.toml) ───────────────────────────────────

#[derive(Debug, Deserialize, Default)]
pub(crate) struct MappingsToml {
    #[serde(default)]
    pub(crate) meta: MetaSection,
    #[serde(default)]
    pub(crate) field_mappings: HashMap<String, String>,
    #[serde(default)]
    pub(crate) ocsf_field_renames: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Default)]
pub(crate) struct MetaSection {
    #[serde(default = "default_ocsf_version")]
    pub(crate) ocsf_version: String,
}

pub(crate) fn default_ocsf_version() -> String { "1.7.0".to_string() }

/// Standard OCSF mapping targets that correspond to typed ClickHouse columns in
/// `OcsfRecord`.  Any `field_mappings.toml` value NOT in this list is an
/// "unknown target" — it lands in the `extensions` JSON column and is also
/// auto-promoted to its own dedicated ClickHouse column via
/// `MATERIALIZED JSONExtractString(extensions, '<target>')`.
pub(crate) const STANDARD_OCSF_TARGETS: &[&str] = &[
    "src_ip", "dst_ip", "src_port", "dst_port",
    "nat_src_ip", "nat_dst_ip", "nat_src_port", "nat_dst_port",
    "actor_user", "target_user", "domain",
    "url", "http_method", "http_status", "app_name",
    "src_hostname", "dst_hostname",
    "file_name", "process_name", "process_id",
    "rule_name", "category", "action", "status",
    "interface_in", "interface_out",
    "bytes_in", "bytes_out", "network_protocol",
];

/// Runtime-ready custom mappings, shared via `Arc<RwLock<_>>`.
#[derive(Debug, Default)]
pub struct CustomMappings {
    pub ocsf_version:  String,
    pub field_map:     HashMap<String, String>,
    pub ocsf_renames:  HashMap<String, String>,
}

impl CustomMappings {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read {}", path.display()))?;
        let parsed: MappingsToml = toml::from_str(&text)
            .with_context(|| format!("parse {}", path.display()))?;
        Ok(Self {
            ocsf_version: parsed.meta.ocsf_version,
            field_map:    parsed.field_mappings,
            ocsf_renames: parsed.ocsf_field_renames,
        })
    }

    pub fn default() -> Self {
        Self {
            ocsf_version: default_ocsf_version(),
            field_map:    HashMap::new(),
            ocsf_renames: HashMap::new(),
        }
    }

    /// Returns all `field_map` target values that are NOT standard OCSF typed
    /// columns.  These currently land in `extensions` JSON and are candidates
    /// for automatic ClickHouse column creation.
    pub(crate) fn custom_column_targets(&self) -> Vec<String> {
        self.field_map.values()
            .filter(|t| !STANDARD_OCSF_TARGETS.contains(&t.as_str()))
            .cloned()
            .collect()
    }
}
