use clickhouse::Row;
use serde::{Deserialize, Serialize};

// ─── OCSF Record ──────────────────────────────────────────────────────────────

/// Unified OCSF event record.
///
/// `class_uid` is set dynamically by `classify_event()` so every alert is
/// tagged with the correct OCSF class (Authentication, Network Activity,
/// Process Activity, …) rather than always defaulting to Detection Finding.
/// All OCSF 1.7.0 classes across 6 categories are supported.
///
/// Typed columns enable fast ClickHouse skip-index queries and Grafana
/// correlation dashboards.  `event_data` (full Wazuh `data.*`), `extensions`
/// (custom-mapped extras), and `unmapped` (uncaptured top-level keys) ensure
/// that absolutely no data is ever silently dropped.
#[derive(Debug, Clone, Serialize, Deserialize, Row)]
pub(crate) struct OcsfRecord {
    // ── Time ──────────────────────────────────────────────────────────────
    /// Unix epoch seconds — stored as DateTime in ClickHouse.
    pub(crate) time:              u32,
    /// ISO-8601 string for human readability.
    pub(crate) time_dt:           String,

    // ── OCSF metadata ─────────────────────────────────────────────────────
    /// OCSF schema version from config (e.g. "1.7.0").
    pub(crate) ocsf_version:      String,
    pub(crate) class_uid:         u32,
    pub(crate) class_name:        String,
    pub(crate) category_uid:      u32,
    pub(crate) category_name:     String,
    pub(crate) severity_id:       u8,
    pub(crate) severity:          String,
    pub(crate) activity_id:       u8,
    pub(crate) activity_name:     String,
    /// `class_uid * 100 + activity_id` — OCSF 1.7.0 required derived field.
    pub(crate) type_uid:          u32,
    pub(crate) status_id:         u8,
    pub(crate) confidence_id:     u8,
    pub(crate) status:            String,
    pub(crate) action:            String,

    // ── Device / agent ────────────────────────────────────────────────────
    pub(crate) device_uid:        String,
    pub(crate) device_name:       String,
    pub(crate) device_ip:         String,

    // ── Network layer ─────────────────────────────────────────────────────
    pub(crate) src_ip:            String,
    pub(crate) dst_ip:            String,
    pub(crate) src_port:          u16,
    pub(crate) dst_port:          u16,
    pub(crate) nat_src_ip:        String,
    pub(crate) nat_dst_ip:        String,
    pub(crate) nat_src_port:      u16,
    pub(crate) nat_dst_port:      u16,
    pub(crate) network_protocol:  String,
    pub(crate) bytes_in:          u64,
    pub(crate) bytes_out:         u64,

    // ── User / actor ──────────────────────────────────────────────────────
    pub(crate) actor_user:        String,
    pub(crate) target_user:       String,
    pub(crate) domain:            String,

    // ── HTTP / Application ────────────────────────────────────────────────
    pub(crate) url:               String,
    pub(crate) http_method:       String,
    pub(crate) http_status:       u16,
    pub(crate) app_name:          String,

    // ── Endpoint / Process ────────────────────────────────────────────────
    pub(crate) src_hostname:      String,
    pub(crate) dst_hostname:      String,
    pub(crate) file_name:         String,
    pub(crate) process_name:      String,
    pub(crate) process_id:        u32,

    // ── Network routing ───────────────────────────────────────────────────
    pub(crate) interface_in:      String,
    pub(crate) interface_out:     String,

    // ── Threat / category ─────────────────────────────────────────────────
    pub(crate) rule_name:         String,
    pub(crate) app_category:      String,

    // ── Finding (Wazuh rule) ──────────────────────────────────────────────
    pub(crate) finding_title:     String,
    pub(crate) finding_uid:       String,
    pub(crate) finding_types:     String,
    pub(crate) wazuh_rule_level:  u8,
    pub(crate) wazuh_fired_times: u32,
    pub(crate) pci_dss:           String,
    pub(crate) gdpr:              String,
    pub(crate) hipaa:             String,
    pub(crate) nist_800_53:       String,

    // ── MITRE ATT&CK ─────────────────────────────────────────────────────
    pub(crate) attack_technique:  String,
    pub(crate) attack_id:         String,
    pub(crate) attack_tactic:     String,

    // ── Vulnerability (class 2002) ────────────────────────────────────────
    /// CVE identifier e.g. "CVE-2024-12345" — empty for non-vuln classes.
    pub(crate) cve_id:            String,
    /// CVSS v3 base score 0.0–10.0 — zero for non-vuln classes.
    pub(crate) cvss_score:        f32,

    // ── Source metadata ───────────────────────────────────────────────────
    pub(crate) src_location:      String,
    pub(crate) decoder_name:      String,
    pub(crate) manager_name:      String,

    // ── Lossless capture ─────────────────────────────────────────────────
    pub(crate) event_data:        String,
    pub(crate) extensions:        String,
    pub(crate) unmapped:          String,
    pub(crate) raw_data:          String,
}
