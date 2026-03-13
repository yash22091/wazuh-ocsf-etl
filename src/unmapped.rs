use std::collections::{HashMap, HashSet};
use std::path::Path;

use once_cell::sync::Lazy;
use serde_json::Value;
use tracing::warn;

use crate::config::CustomMappings;
use crate::field_paths::{
    SRC_IP, DST_IP, SRC_PORT, DST_PORT,
    NAT_SRC_IP, NAT_DST_IP, NAT_SRC_PORT, NAT_DST_PORT,
    PROTOCOL, BYTES_IN, BYTES_OUT,
    ACTOR_USER, TARGET_USER, DOMAIN, URL,
    HTTP_METHOD, HTTP_STATUS, APP_NAME,
    FILE_NAME, PROCESS_NAME, PROCESS_ID,
    RULE_NAME, CATEGORY,
    IFACE_IN, IFACE_OUT, SRC_HOSTNAME, DST_HOSTNAME,
    ACTION, STATUS,
};
use crate::json::flatten_to_paths;

// ─── Unmapped-field discovery ─────────────────────────────────────────────────

/// Union of every field path across all static constant arrays PLUS every path
/// that is natively extracted in transform.rs.  Paths in this set never appear
/// in the unmapped-fields report, keeping the report focused on truly unknown
/// site-specific fields.
static KNOWN_PATHS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut s = HashSet::new();
    for paths in &[
        SRC_IP, DST_IP, SRC_PORT, DST_PORT,
        NAT_SRC_IP, NAT_DST_IP, NAT_SRC_PORT, NAT_DST_PORT,
        PROTOCOL, BYTES_IN, BYTES_OUT,
        ACTOR_USER, TARGET_USER, DOMAIN, URL,
        HTTP_METHOD, HTTP_STATUS, APP_NAME,
        FILE_NAME, PROCESS_NAME, PROCESS_ID,
        RULE_NAME, CATEGORY,
        IFACE_IN, IFACE_OUT, SRC_HOSTNAME, DST_HOSTNAME,
        ACTION, STATUS,
    ] {
        for p in *paths { s.insert(*p); }
    }

    // ── Wazuh Vulnerability Detector (natively extracted in transform.rs) ──
    for p in &[
        "vulnerability.cve",
        "vulnerability.title",
        "vulnerability.severity",
        "vulnerability.score.base",
        "vulnerability.score.version",
        "vulnerability.cvss.cvss3.base_score",
        "vulnerability.cvss.cvss3.vector.attack_vector",
        "vulnerability.cvss.cvss3.vector.availability",
        "vulnerability.cvss.cvss3.vector.confidentiality_impact",
        "vulnerability.cvss.cvss3.vector.integrity_impact",
        "vulnerability.cvss.cvss3.vector.privileges_required",
        "vulnerability.cvss.cvss3.vector.scope",
        "vulnerability.cvss.cvss3.vector.user_interaction",
        "vulnerability.status",
        "vulnerability.reference",
        "vulnerability.package.name",
        "vulnerability.package.version",
        "vulnerability.package.architecture",
        "vulnerability.package.condition",
        "vulnerability.package.source",
        "vulnerability.published",
        "vulnerability.updated",
        "vulnerability.enumeration",
        "vulnerability.classification",
        "vulnerability.type",
        "vulnerability.assigner",
        "vulnerability.cwe_reference",
        "vulnerability.rationale",
        "vulnerability.scanner.reference",
    ] { s.insert(p); }

    // ── Windows Event Log (natively extracted in transform.rs) ─────────────
    for p in &[
        "win.system.providerName",
        "win.system.providerGuid",
        "win.system.processID",
        "win.system.eventID",
        "win.system.channel",
        "win.system.message",
        "win.system.severityValue",
        "win.system.eventRecordID",
        "win.system.keywords",
        "win.system.level",
        "win.system.opcode",
        "win.system.systemTime",
        "win.system.task",
        "win.system.threadID",
        "win.system.version",
        "win.system.eventSourceName",
        "win.eventdata.processName",
        "win.eventdata.logonType",
        "win.eventdata.authenticationPackageName",
        "win.eventdata.subjectUserSid",
        "win.eventdata.subjectUserName",
        "win.eventdata.subjectLogonId",
        "win.eventdata.targetUserSid",
        "win.eventdata.targetUserName",
        "win.eventdata.targetLogonId",
        "win.eventdata.targetLinkedLogonId",
        "win.eventdata.elevatedToken",
        "win.eventdata.impersonationLevel",
        "win.eventdata.keyLength",
        "win.eventdata.logonGuid",
        "win.eventdata.logonProcessName",
        "win.eventdata.virtualAccount",
        "win.eventdata.privilegeList",
        "win.eventdata.algorithmName",
        "win.eventdata.keyName",
        "win.eventdata.keyType",
        "win.eventdata.operation",
        "win.eventdata.providerName",
        "win.eventdata.returnCode",
        "win.eventdata.address",
        "win.eventdata.addressLength",
        "win.eventdata.queryName",
        "win.eventdata.data",
    ] { s.insert(p); }

    // ── dpkg / apt Package Audit (natively extracted in transform.rs) ──────
    for p in &["package", "version", "arch", "dpkg_status"] { s.insert(p); }

    // ── Process / sudo context (natively extracted in transform.rs) ─────────
    for p in &["uid", "tty", "pwd"] { s.insert(p); }

    s
});

/// Per-field stats accumulated at runtime.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct FieldInfo {
    pub(crate) count:          u64,
    pub(crate) example:        String,
    pub(crate) suggested_toml: String,
}

/// Global accumulator for unmapped field paths.
pub(crate) static UNMAPPED_TRACKER: Lazy<std::sync::Mutex<HashMap<String, FieldInfo>>> =
    Lazy::new(|| std::sync::Mutex::new(HashMap::new()));

/// Called at the end of `transform()`.  Records any data.* paths not covered
/// by the static constants or custom mappings.
pub(crate) fn track_unmapped_fields(data_val: &Value, custom: &CustomMappings) {
    let mut leaves: Vec<(String, String)> = Vec::new();
    flatten_to_paths(data_val, "", &mut leaves);

    if leaves.is_empty() { return; }

    let custom_keys: HashSet<&str> = custom.field_map.keys()
        .map(|s| s.as_str())
        .collect();

    let mut guard = match UNMAPPED_TRACKER.lock() {
        Ok(g)  => g,
        Err(e) => e.into_inner(),
    };

    for (path, example) in leaves {
        if KNOWN_PATHS.contains(path.as_str()) { continue; }
        if custom_keys.contains(path.as_str()) { continue; }

        let entry = guard.entry(path.clone()).or_insert_with(|| FieldInfo {
            count:   0,
            example: example.clone(),
            suggested_toml: format!(
                r#"# "{path}" = "src_ip"  # TODO: choose a valid target column"#
            ),
        });
        entry.count += 1;
        if !example.is_empty() {
            entry.example = example;
        }
    }
}

/// Serialize UNMAPPED_TRACKER to `path` atomically (write temp → rename).
pub(crate) fn write_unmapped_report(path: &Path) {
    let guard = match UNMAPPED_TRACKER.lock() {
        Ok(g)  => g,
        Err(e) => e.into_inner(),
    };
    if guard.is_empty() { return; }

    let mut fields: Vec<(&String, &FieldInfo)> = guard.iter().collect();
    fields.sort_by(|a, b| b.1.count.cmp(&a.1.count).then(a.0.cmp(b.0)));

    let fields_map: serde_json::Map<String, Value> = fields.into_iter()
        .map(|(k, v)| (k.clone(), serde_json::to_value(v).unwrap_or(Value::Null)))
        .collect();

    let doc = serde_json::json!({
        "note": "Fields from data.* that are not yet mapped to an OCSF typed column. \
                 Add entries to config/field_mappings.toml to promote them.",
        "valid_targets": [
            "src_ip","dst_ip","src_port","dst_port",
            "nat_src_ip","nat_dst_ip","nat_src_port","nat_dst_port",
            "actor_user","target_user","domain","url",
            "http_method","http_status","app_name","src_hostname","dst_hostname",
            "file_name","process_name","process_id","rule_name","app_category",
            "interface_in","interface_out","bytes_in","bytes_out",
            "network_protocol","action","status"
        ],
        "fields": fields_map,
    });

    let tmp = path.with_extension("json.tmp");
    match std::fs::write(&tmp, serde_json::to_string_pretty(&doc).unwrap_or_default()) {
        Ok(_) => {
            if let Err(e) = std::fs::rename(&tmp, path) {
                warn!("unmapped_fields: rename failed: {e}");
                let _ = std::fs::remove_file(&tmp);
            }
        }
        Err(e) => warn!("unmapped_fields: write failed: {e}"),
    }
}
