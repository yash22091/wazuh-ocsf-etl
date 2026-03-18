use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{Map, Value};
use chrono::{DateTime, Utc};
use tracing::debug;

use crate::classify::{classify_event, map_severity};
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
use crate::json::{first_str, first_port, first_u64, get_data_field, jpath};
use crate::record::OcsfRecord;
use crate::unmapped::track_unmapped_fields;
use crate::validator::check_and_warn;

// ─── Sanitise / route ─────────────────────────────────────────────────────────

static SANITIZE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[^a-zA-Z0-9_]+").unwrap());

pub(crate) fn sanitize_name(raw: &str) -> String {
    SANITIZE_RE
        .replace_all(raw, "_")
        .to_lowercase()
        .trim_matches('_')
        .to_string()
}

/// Determine the ClickHouse table for a Wazuh alert.
pub(crate) fn routing_table(
    db:           &str,
    agent_name:   &str,
    location:     &str,
    special_locs: &[String],
) -> String {
    let seg = if !location.is_empty()
        && special_locs.iter().any(|s| s.as_str() == location)
    {
        sanitize_name(location)
    } else {
        let n = sanitize_name(agent_name);
        if n.is_empty() { "unknown_agent".to_string() } else { n }
    };
    let tbl: String = format!("ocsf_{seg}").chars().take(200).collect();
    format!("{db}.{tbl}")
}

// ─── Transform ────────────────────────────────────────────────────────────────

/// Parse one raw Wazuh alert line → `(table_name, OcsfRecord)`.
/// Returns `None` only when the line is not valid JSON.
pub(crate) fn transform(
    raw:          &str,
    db:           &str,
    special_locs: &[String],
    custom:       &CustomMappings,
) -> Option<(String, OcsfRecord)> {
    if raw.trim().is_empty() { return None; }
    let v: Value = serde_json::from_str(raw)
        .map_err(|e| debug!("JSON parse (line skipped): {e}"))
        .ok()?;
    let obj = v.as_object()?;

    let empty_map = Map::new();
    let section = |k: &str| obj.get(k).and_then(Value::as_object).unwrap_or(&empty_map);
    let get     = |m: &Map<String, Value>, k: &str| -> String {
        m.get(k).and_then(Value::as_str).unwrap_or("").to_string()
    };

    let agent    = section("agent");
    let rule     = section("rule");
    let manager  = section("manager");
    let decoder  = section("decoder");
    let syscheck = section("syscheck");
    let syscheck_event = get(syscheck, "event");

    // ── Timestamp ─────────────────────────────────────────────────────────
    let ts = obj.get("@timestamp").or_else(|| obj.get("timestamp"))
        .and_then(Value::as_str).unwrap_or("");
    let (time_secs, time_dt) = ts.parse::<DateTime<Utc>>()
        .map(|dt| (dt.timestamp() as u32, dt.to_rfc3339()))
        .unwrap_or_else(|_| {
            let now = Utc::now();
            (now.timestamp() as u32, now.to_rfc3339())
        });

    // ── Agent / device ────────────────────────────────────────────────────
    let agent_id   = get(agent, "id");
    let agent_name = get(agent, "name");
    let agent_ip   = get(agent, "ip");

    // ── Rule / finding ────────────────────────────────────────────────────
    let rule_id    = get(rule, "id");
    let rule_desc  = get(rule, "description");
    let rule_level = rule.get("level").and_then(Value::as_u64).unwrap_or(0);
    let rule_fired_times = rule.get("firedtimes").and_then(Value::as_u64).unwrap_or(0) as u32;
    // finding_title can be overridden by decoder-specific extraction (e.g. sca.check.title).
    // finding_uid is ALWAYS rule_id — Wazuh rule ID must never be replaced.
    let mut finding_title_override = String::new();
    let rule_groups: Vec<&str> = rule.get("groups")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let finding_types = serde_json::to_string(&rule_groups)
        .unwrap_or_else(|_| "[]".into());
    let compliance_str = |key: &str| -> String {
        rule.get(key)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(","))
            .unwrap_or_default()
    };
    let pci_dss     = compliance_str("pci_dss");
    let gdpr        = compliance_str("gdpr");
    let hipaa       = compliance_str("hipaa");
    let nist_800_53 = compliance_str("nist_800_53");

    // ── MITRE ATT&CK ─────────────────────────────────────────────────────
    let mitre = rule.get("mitre");
    let json_arr = |key: &str| -> String {
        mitre.and_then(|m| m.get(key))
            .map(|v| serde_json::to_string(v).unwrap_or_default())
            .unwrap_or_default()
    };

    // ── Location / routing / metadata ─────────────────────────────────────
    let location     = obj.get("location").and_then(Value::as_str).unwrap_or("");
    let manager_name = get(manager, "name");
    let decoder_name = get(decoder, "name");
    let (base_sev_id, base_sev_label) = map_severity(rule_level);
    let mut sev_id:    u8     = base_sev_id;
    let mut sev_label: String = base_sev_label.to_string();

    // ── data sub-object ───────────────────────────────────────────────────
    let data_val = obj.get("data")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));

    let mut src_ip           = first_str(&data_val, SRC_IP);
    let mut dst_ip           = first_str(&data_val, DST_IP);
    let mut src_port         = first_port(&data_val, SRC_PORT);
    let mut dst_port         = first_port(&data_val, DST_PORT);
    let mut nat_src_ip       = first_str(&data_val, NAT_SRC_IP);
    let mut nat_dst_ip       = first_str(&data_val, NAT_DST_IP);
    let mut nat_src_port     = first_port(&data_val, NAT_SRC_PORT);
    let mut nat_dst_port     = first_port(&data_val, NAT_DST_PORT);
    let mut network_protocol = first_str(&data_val, PROTOCOL);
    let mut bytes_in         = first_u64(&data_val, BYTES_IN);
    let mut bytes_out        = first_u64(&data_val, BYTES_OUT);
    let mut actor_user       = first_str(&data_val, ACTOR_USER);
    let mut target_user      = first_str(&data_val, TARGET_USER);
    let mut domain           = first_str(&data_val, DOMAIN);
    let mut url              = first_str(&data_val, URL);
    let mut http_method      = first_str(&data_val, HTTP_METHOD);
    let mut http_status      = first_port(&data_val, HTTP_STATUS);
    let mut app_name         = first_str(&data_val, APP_NAME);
    let mut src_hostname     = first_str(&data_val, SRC_HOSTNAME);
    let mut dst_hostname     = first_str(&data_val, DST_HOSTNAME);
    let mut file_name        = first_str(&data_val, FILE_NAME);
    let mut process_name     = first_str(&data_val, PROCESS_NAME);
    let mut process_id       = first_port(&data_val, PROCESS_ID) as u32;
    let mut interface_in     = first_str(&data_val, IFACE_IN);
    let mut interface_out    = first_str(&data_val, IFACE_OUT);
    let mut rule_name        = first_str(&data_val, RULE_NAME);
    let mut app_category     = first_str(&data_val, CATEGORY);
    let mut action           = first_str(&data_val, ACTION);
    let mut status           = first_str(&data_val, STATUS);

    // ── Wazuh Vulnerability Detector (data.vulnerability.*) ──────────────
    // Natively extracted — no field_mappings.toml entry required.
    let mut cve_id     = String::new();
    let mut cvss_score = 0.0_f32;
    let mut vuln_sev   = String::new();
    {
        let cve = jpath(&data_val, "vulnerability.cve");
        if !cve.is_empty() {
            cve_id   = cve.to_string();
            vuln_sev = jpath(&data_val, "vulnerability.severity").to_string();
            // CVSS score — use get_data_field so numeric JSON values (e.g. 9.8) are
            // coerced to string before parsing; jpath only handles string leaves.
            let score_str = {
                let s = get_data_field(&data_val, "vulnerability.cvss.cvss3.base_score");
                if !s.is_empty() { s } else { get_data_field(&data_val, "vulnerability.score.base") }
            };
            cvss_score = score_str.parse::<f32>().unwrap_or(0.0);
            // Backfill existing typed columns if not already set
            if url.is_empty()      { url      = jpath(&data_val, "vulnerability.reference").to_string(); }
            if app_name.is_empty() { app_name = jpath(&data_val, "vulnerability.package.name").to_string(); }
            if status.is_empty()   { status   = jpath(&data_val, "vulnerability.status").to_string(); }
        }
    }

    // ── Windows Event Log (data.win.*) ────────────────────────────────────
    // Natively extracted — no field_mappings.toml entry required.
    if app_name.is_empty()     { let v = jpath(&data_val, "win.system.providerName");   if !v.is_empty() { app_name     = v.to_string(); } }
    if process_id == 0         { let v = jpath(&data_val, "win.system.processID");       if !v.is_empty() { process_id   = v.parse().unwrap_or(0); } }
    if process_name.is_empty() { let v = jpath(&data_val, "win.eventdata.processName");  if !v.is_empty() { process_name = v.to_string(); } }
    if actor_user.is_empty() {
        // prefer human-readable name, fall back to SID
        let v = jpath(&data_val, "win.eventdata.subjectUserName");
        let v = if v.is_empty() { jpath(&data_val, "win.eventdata.subjectUserSid") } else { v };
        if !v.is_empty() { actor_user = v.to_string(); }
    }
    if target_user.is_empty() {
        let v = jpath(&data_val, "win.eventdata.targetUserName");
        let v = if v.is_empty() { jpath(&data_val, "win.eventdata.targetUserSid") } else { v };
        if !v.is_empty() { target_user = v.to_string(); }
    }

    // ── dpkg / apt Package Audit (data.package, data.arch, …) ────────────
    // Natively extracted — no field_mappings.toml entry required.
    if app_name.is_empty()   { if let Some(s) = data_val.get("package").and_then(Value::as_str)    { if !s.is_empty() { app_name = s.to_string(); } } }
    if status.is_empty()     { if let Some(s) = data_val.get("dpkg_status").and_then(Value::as_str) { if !s.is_empty() { status   = s.to_string(); } } }

    // ── Syscheck (FIM) top-level section ─────────────────────────────────
    // syscheck.path → file_name; hashes and attrs go to extensions.
    // Natively extracted — no field_mappings.toml entry required.
    let empty_map2 = Map::new();
    let syscheck_obj = obj.get("syscheck").and_then(Value::as_object).unwrap_or(&empty_map2);
    let get_sc = |k: &str| -> String {
        syscheck_obj.get(k).and_then(Value::as_str).unwrap_or("").to_string()
    };
    if file_name.is_empty() {
        let p = get_sc("path");
        if !p.is_empty() { file_name = p; }
    }

    // ── predecoder (Wazuh top-level section) ──────────────────────────────
    // predecoder.hostname → src_hostname; predecoder.program_name → app_name.
    let predecoder = obj.get("predecoder").and_then(Value::as_object).unwrap_or(&empty_map2);
    if src_hostname.is_empty() {
        let h = predecoder.get("hostname").and_then(Value::as_str).unwrap_or("");
        if !h.is_empty() { src_hostname = h.to_string(); }
    }
    if app_name.is_empty() {
        let p = predecoder.get("program_name").and_then(Value::as_str).unwrap_or("");
        if !p.is_empty() { app_name = p.to_string(); }
    }

    // ── SCA (Security Configuration Assessment) — class 2003 ─────────────
    // sca.check.* live inside the data sub-object when Wazuh fires SCA rules.
    // Map them to the most appropriate typed OCSF/ClickHouse columns so that
    // Compliance Finding rows have meaningful typed values, not just raw_data.
    {
        // finding_title: prefer sca.check.title over the generic rule description
        if finding_title_override.is_empty() {
            let v = jpath(&data_val, "sca.check.title");
            if !v.is_empty() { finding_title_override = v.to_string(); }
        }
        // sca.check.id goes into extensions — rule_id (finding_uid) is never replaced
        // status: sca.check.result → "pass" | "fail" | "not applicable"
        if status.is_empty() {
            let v = jpath(&data_val, "sca.check.result");
            if !v.is_empty() { status = v.to_string(); }
        }
        // app_name: sca.policy is the benchmark name (e.g. "CIS Microsoft Windows 10")
        if app_name.is_empty() {
            let v = jpath(&data_val, "sca.policy");
            if !v.is_empty() { app_name = v.to_string(); }
        }
    }

    // ── Linux audit / SELinux AVC events ─────────────────────────────────
    // audit.directory.name is the path being accessed (maps to file_name).
    // audit.id goes into extensions — rule_id (finding_uid) is never replaced.
    {
        if file_name.is_empty() {
            let v = jpath(&data_val, "audit.directory.name");
            if !v.is_empty() { file_name = v.to_string(); }
        }
    }

    // ── Custom mapping overlay ────────────────────────────────────────────
    // Only for site-specific decoder fields not handled above.
    let mut extensions: Map<String, Value> = Map::new();
    // Add win-specific context into extensions (win_event_id, win_channel, win_logon_type)
    { let v = jpath(&data_val, "win.system.eventID");         if !v.is_empty() { extensions.insert("win_event_id".into(),   Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "win.system.channel");         if !v.is_empty() { extensions.insert("win_channel".into(),    Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "win.eventdata.logonType");    if !v.is_empty() { extensions.insert("win_logon_type".into(), Value::String(v.to_string())); } }
    // Windows SCM positional parameters (context-dependent per Event ID — store verbatim)
    for i in 1u8..=7 {
        let key = format!("win.eventdata.param{i}");
        let v = jpath(&data_val, &key);
        if !v.is_empty() { extensions.insert(format!("win_param{i}"), Value::String(v.to_string())); }
    }
    // Windows raw event binary (hex-encoded)
    { let v = jpath(&data_val, "win.eventdata.binary"); if !v.is_empty() { extensions.insert("win_event_binary".into(), Value::String(v.to_string())); } }
    // SCA extended context (check details beyond the typed columns above)
    { let v = jpath(&data_val, "sca.scan_id");                if !v.is_empty() { extensions.insert("sca_scan_id".into(),         Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.check.id");               if !v.is_empty() { extensions.insert("sca_check_id".into(),        Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.check.compliance.cis");   if !v.is_empty() { extensions.insert("sca_cis_control".into(),     Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.check.compliance.cis_csc"); if !v.is_empty() { extensions.insert("sca_cis_csc".into(),       Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.check.description");      if !v.is_empty() { extensions.insert("sca_description".into(),    Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.check.rationale");        if !v.is_empty() { extensions.insert("sca_rationale".into(),      Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.check.remediation");      if !v.is_empty() { extensions.insert("sca_remediation".into(),    Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.check.reason");           if !v.is_empty() { extensions.insert("sca_reason".into(),         Value::String(v.to_string())); } }
    // SCA extended compliance framework tags (multiple standards observed in the field)
    { let v = jpath(&data_val, "sca.check.compliance.cis_csc_v7");        if !v.is_empty() { extensions.insert("sca_cis_csc_v7".into(),         Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.check.compliance.cis_csc_v8");        if !v.is_empty() { extensions.insert("sca_cis_csc_v8".into(),         Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.check.compliance.cmmc_v2.0");         if !v.is_empty() { extensions.insert("sca_cmmc_v2".into(),            Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.check.compliance.hipaa");             if !v.is_empty() { extensions.insert("sca_hipaa".into(),               Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.check.compliance.iso_27001-2013");    if !v.is_empty() { extensions.insert("sca_iso_27001".into(),           Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.check.compliance.mitre_mitigations"); if !v.is_empty() { extensions.insert("sca_mitre_mitigations".into(),   Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.check.compliance.mitre_tactics");     if !v.is_empty() { extensions.insert("sca_mitre_tactics".into(),       Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.check.compliance.mitre_techniques");  if !v.is_empty() { extensions.insert("sca_mitre_techniques".into(),    Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.check.compliance.nist_sp_800-53");    if !v.is_empty() { extensions.insert("sca_nist_800_53".into(),         Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.check.compliance.pci_dss_v3.2.1");   if !v.is_empty() { extensions.insert("sca_pci_dss_v3".into(),          Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.check.compliance.pci_dss_v4.0");     if !v.is_empty() { extensions.insert("sca_pci_dss_v4".into(),          Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.check.compliance.soc_2");            if !v.is_empty() { extensions.insert("sca_soc2".into(),                 Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.check.command.0");                   if !v.is_empty() { extensions.insert("sca_check_command".into(),        Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.check.file.0");                      if !v.is_empty() { extensions.insert("sca_check_file".into(),           Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.check.references");                  if !v.is_empty() { extensions.insert("sca_references".into(),           Value::String(v.to_string())); } }
    // SCA policy-level summary fields (scan result overview rows)
    { let v = jpath(&data_val, "sca.policy_id");     if !v.is_empty() { extensions.insert("sca_policy_id".into(),          Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.description");   if !v.is_empty() { extensions.insert("sca_policy_description".into(), Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.file");          if !v.is_empty() { extensions.insert("sca_policy_file".into(),        Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.score");         if !v.is_empty() { extensions.insert("sca_score".into(),              Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.total_checks");  if !v.is_empty() { extensions.insert("sca_total_checks".into(),       Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.passed");        if !v.is_empty() { extensions.insert("sca_passed_count".into(),       Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.failed");        if !v.is_empty() { extensions.insert("sca_failed_count".into(),       Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "sca.invalid");       if !v.is_empty() { extensions.insert("sca_invalid_count".into(),      Value::String(v.to_string())); } }
    // Linux audit AVC context
    { let v = jpath(&data_val, "audit.type");                 if !v.is_empty() { extensions.insert("audit_type".into(),         Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "audit.id");                   if !v.is_empty() { extensions.insert("audit_id".into(),           Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "audit.euid");                 if !v.is_empty() { extensions.insert("audit_euid".into(),         Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "audit.uid");                  if !v.is_empty() { extensions.insert("audit_uid".into(),          Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "audit.gid");                  if !v.is_empty() { extensions.insert("audit_gid".into(),          Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "audit.session");              if !v.is_empty() { extensions.insert("audit_session".into(),      Value::String(v.to_string())); } }
    // FIM / syscheck hash digests
    { let v = get_sc("md5_after");    if !v.is_empty() { extensions.insert("fim_md5".into(),    Value::String(v)); } }
    { let v = get_sc("sha1_after");   if !v.is_empty() { extensions.insert("fim_sha1".into(),   Value::String(v)); } }
    { let v = get_sc("sha256_after"); if !v.is_empty() { extensions.insert("fim_sha256".into(), Value::String(v)); } }
    { let v = get_sc("size_after");   if !v.is_empty() { extensions.insert("fim_size".into(),   Value::String(v)); } }
    { let v = get_sc("mode");         if !v.is_empty() { extensions.insert("fim_mode".into(),   Value::String(v)); } }
    if let Some(ca) = syscheck_obj.get("changed_attributes") {
        if let Ok(s) = serde_json::to_string(ca) { extensions.insert("fim_changed_attrs".into(), Value::String(s)); }
    }
    // dpkg package version + arch
    if let Some(s) = data_val.get("version").and_then(Value::as_str) { if !s.is_empty() { extensions.insert("package_version".into(), Value::String(s.to_string())); } }
    if let Some(s) = data_val.get("arch").and_then(Value::as_str)    { if !s.is_empty() { extensions.insert("package_arch".into(),    Value::String(s.to_string())); } }
    // Process / sudo context
    if let Some(s) = data_val.get("uid").and_then(Value::as_str) { if !s.is_empty() { extensions.insert("actor_uid".into(),   Value::String(s.to_string())); } }
    if let Some(s) = data_val.get("tty").and_then(Value::as_str) { if !s.is_empty() { extensions.insert("tty".into(),         Value::String(s.to_string())); } }
    if let Some(s) = data_val.get("pwd").and_then(Value::as_str) { if !s.is_empty() { extensions.insert("working_dir".into(), Value::String(s.to_string())); } }
    // Other generic decoder context fields
    if file_name.is_empty() {
        if let Some(s) = data_val.get("file").and_then(Value::as_str) { if !s.is_empty() { file_name = s.to_string(); } }
    }
    if finding_title_override.is_empty() {
        if let Some(s) = data_val.get("title").and_then(Value::as_str) { if !s.is_empty() { finding_title_override = s.to_string(); } }
    }
    if let Some(s) = data_val.get("gid").and_then(Value::as_str)   { if !s.is_empty() { extensions.insert("actor_gid".into(),      Value::String(s.to_string())); } }
    if let Some(s) = data_val.get("home").and_then(Value::as_str)  { if !s.is_empty() { extensions.insert("actor_home_dir".into(), Value::String(s.to_string())); } }
    if let Some(s) = data_val.get("shell").and_then(Value::as_str) { if !s.is_empty() { extensions.insert("actor_shell".into(),    Value::String(s.to_string())); } }

    // ── AWS CloudTrail / AWS integration (data.aws.*) ─────────────────────
    // Natively extracted — no field_mappings.toml entry required.
    // Covers CloudTrail management/data events forwarded via Wazuh's
    // aws-cloudtrail decoder (integration = "aws").
    if let Some(aws) = data_val.get("aws").and_then(Value::as_object) {
        macro_rules! aws_str {
            ($obj:expr, $key:expr) => {
                $obj.get($key).and_then(Value::as_str).unwrap_or("")
            };
        }
        macro_rules! aws_ext {
            ($key:expr, $ext:expr) => {
                let _v = aws_str!(aws, $key);
                if !_v.is_empty() { extensions.insert($ext.into(), Value::String(_v.to_string())); }
            };
        }

        // src_ip: source_ip_address (snake_case variant; also covered by field_paths)
        if src_ip.is_empty() {
            let v = aws_str!(aws, "source_ip_address");
            if !v.is_empty() { src_ip = v.to_string(); }
        }
        // actor_user: additionalEventData.UserName (human email) → userIdentity.arn
        if actor_user.is_empty() {
            if let Some(aed) = aws.get("additionalEventData").and_then(Value::as_object) {
                let v = aws_str!(aed, "UserName");
                if !v.is_empty() { actor_user = v.to_string(); }
            }
        }
        if actor_user.is_empty() {
            if let Some(uid) = aws.get("userIdentity").and_then(Value::as_object) {
                let v = aws_str!(uid, "arn");
                if !v.is_empty() { actor_user = v.to_string(); }
            }
        }
        // domain: AWS account ID
        if domain.is_empty() {
            let v = aws_str!(aws, "aws_account_id");
            if !v.is_empty() { domain = v.to_string(); }
        }
        // action: eventType (e.g. "AwsApiCall", "AwsConsoleAction", "AwsServiceEvent")
        if action.is_empty() {
            let v = aws_str!(aws, "eventType");
            if !v.is_empty() { action = v.to_string(); }
        }
        // app_category: eventCategory (e.g. "Management", "Data")
        if app_category.is_empty() {
            let v = aws_str!(aws, "eventCategory");
            if !v.is_empty() { app_category = v.to_string(); }
        }
        // dst_hostname: TLS client-provided host header (the AWS service endpoint)
        if dst_hostname.is_empty() {
            if let Some(tls) = aws.get("tlsDetails").and_then(Value::as_object) {
                let v = aws_str!(tls, "clientProvidedHostHeader");
                if !v.is_empty() { dst_hostname = v.to_string(); }
            }
        }
        // url: additionalEventData.LoginTo (console SSO redirect URL)
        if url.is_empty() {
            if let Some(aed) = aws.get("additionalEventData").and_then(Value::as_object) {
                let v = aws_str!(aed, "LoginTo");
                if !v.is_empty() { url = v.to_string(); }
            }
        }
        // status: ConsoleLogin → UserAuthentication → responseElements.status
        if status.is_empty() {
            if let Some(re) = aws.get("responseElements").and_then(Value::as_object) {
                let v = aws_str!(re, "ConsoleLogin");
                if !v.is_empty() { status = v.to_string(); }
            }
        }
        if status.is_empty() {
            if let Some(sed) = aws.get("serviceEventDetails").and_then(Value::as_object) {
                let v = aws_str!(sed, "UserAuthentication");
                if !v.is_empty() { status = v.to_string(); }
            }
        }
        if status.is_empty() {
            if let Some(re) = aws.get("responseElements").and_then(Value::as_object) {
                let v = aws_str!(re, "status");
                if !v.is_empty() { status = v.to_string(); }
            }
        }
        // errorMessage present only on failed API calls — backfill status = Failure
        {
            let v = aws_str!(aws, "errorMessage");
            if !v.is_empty() {
                if status.is_empty() { status = "Failure".to_string(); }
                extensions.insert("aws_error_message".into(), Value::String(v.to_string()));
            }
        }

        // Event / request metadata
        aws_ext!("eventID",                  "aws_event_id");
        aws_ext!("eventTime",                "aws_event_time");
        aws_ext!("requestID",                "aws_request_id");
        aws_ext!("awsRegion",                "aws_region");
        aws_ext!("userAgent",                "aws_user_agent");
        aws_ext!("recipientAccountId",       "aws_recipient_account_id");
        aws_ext!("sharedEventID",            "aws_shared_event_id");
        aws_ext!("managementEvent",          "aws_management_event");
        aws_ext!("readOnly",                 "aws_read_only");
        aws_ext!("sessionCredentialFromConsole", "aws_session_from_console");
        aws_ext!("source",                   "aws_source");
        aws_ext!("eventVersion",             "aws_event_version");

        // userIdentity sub-fields
        if let Some(uid) = aws.get("userIdentity").and_then(Value::as_object) {
            macro_rules! uid_ext {
                ($key:expr, $ext:expr) => {
                    let _v = aws_str!(uid, $key);
                    if !_v.is_empty() { extensions.insert($ext.into(), Value::String(_v.to_string())); }
                };
            }
            uid_ext!("type",        "aws_identity_type");
            uid_ext!("invokedBy",   "aws_invoked_by");
            uid_ext!("accessKeyId", "aws_access_key_id");
            uid_ext!("credentialId","aws_credential_id");

            // sessionContext sub-fields (role assumption, MFA, federation)
            if let Some(sc) = uid.get("sessionContext").and_then(Value::as_object) {
                // actor_user fallback: role ARN from sessionIssuer when userIdentity.arn is absent
                if actor_user.is_empty() {
                    if let Some(si) = sc.get("sessionIssuer").and_then(Value::as_object) {
                        let v = aws_str!(si, "arn");
                        if !v.is_empty() { actor_user = v.to_string(); }
                    }
                }
                if let Some(si) = sc.get("sessionIssuer").and_then(Value::as_object) {
                    let v = aws_str!(si, "type");        if !v.is_empty() { extensions.insert("aws_session_issuer_type".into(),    Value::String(v.to_string())); }
                    let v = aws_str!(si, "principalId"); if !v.is_empty() { extensions.insert("aws_session_principal_id".into(),   Value::String(v.to_string())); }
                    let v = aws_str!(si, "accountId");   if !v.is_empty() { extensions.insert("aws_session_issuer_account".into(), Value::String(v.to_string())); }
                }
                if let Some(attrs) = sc.get("attributes").and_then(Value::as_object) {
                    let v = aws_str!(attrs, "mfaAuthenticated"); if !v.is_empty() { extensions.insert("aws_session_mfa_auth".into(),    Value::String(v.to_string())); }
                    let v = aws_str!(attrs, "creationDate");     if !v.is_empty() { extensions.insert("aws_session_created_at".into(), Value::String(v.to_string())); }
                }
                if let Some(wif) = sc.get("webIdFederationData").and_then(Value::as_object) {
                    let v = aws_str!(wif, "federatedProvider"); if !v.is_empty() { extensions.insert("aws_federated_provider".into(), Value::String(v.to_string())); }
                }
            }
        }

        // additionalEventData sub-fields
        if let Some(aed) = aws.get("additionalEventData").and_then(Value::as_object) {
            macro_rules! aed_ext {
                ($key:expr, $ext:expr) => {
                    let _v = aws_str!(aed, $key);
                    if !_v.is_empty() { extensions.insert($ext.into(), Value::String(_v.to_string())); }
                };
            }
            aed_ext!("MFAUsed",         "aws_mfa_used");
            aed_ext!("MFAIdentifier",   "aws_mfa_identifier");
            aed_ext!("CredentialType",  "aws_credential_type");
            aed_ext!("AuthWorkflowID",  "aws_auth_workflow_id");
            aed_ext!("MobileVersion",   "aws_mobile_version");
            aed_ext!("keyMaterialId",   "aws_key_material_id");
        }

        // tlsDetails sub-fields
        if let Some(tls) = aws.get("tlsDetails").and_then(Value::as_object) {
            macro_rules! tls_ext {
                ($key:expr, $ext:expr) => {
                    let _v = aws_str!(tls, $key);
                    if !_v.is_empty() { extensions.insert($ext.into(), Value::String(_v.to_string())); }
                };
            }
            tls_ext!("tlsVersion",             "tls_version");
            tls_ext!("cipherSuite",            "tls_cipher_suite");
            tls_ext!("keyExchange",            "tls_key_exchange");
        }

        // resources sub-fields
        if let Some(res) = aws.get("resources").and_then(Value::as_object) {
            macro_rules! res_ext {
                ($key:expr, $ext:expr) => {
                    let _v = aws_str!(res, $key);
                    if !_v.is_empty() { extensions.insert($ext.into(), Value::String(_v.to_string())); }
                };
            }
            res_ext!("ARN",       "aws_resource_arn");
            res_ext!("type",      "aws_resource_type");
            res_ext!("accountId", "aws_resource_account_id");
        }

        // requestParameters sub-fields (KMS, EC2, and other CloudTrail operations)
        if let Some(rp) = aws.get("requestParameters").and_then(Value::as_object) {
            let v = aws_str!(rp, "keyId");             if !v.is_empty() { extensions.insert("aws_kms_key_id".into(),               Value::String(v.to_string())); }
            let v = aws_str!(rp, "networkInterfaceId"); if !v.is_empty() { extensions.insert("aws_req_network_interface_id".into(), Value::String(v.to_string())); }
            let v = aws_str!(rp, "groupId");           if !v.is_empty() { extensions.insert("aws_req_security_group_id".into(),    Value::String(v.to_string())); }
            let v = aws_str!(rp, "subnetId");          if !v.is_empty() { extensions.insert("aws_req_subnet_id".into(),            Value::String(v.to_string())); }
            let v = aws_str!(rp, "snapshotId");        if !v.is_empty() { extensions.insert("aws_req_snapshot_id".into(),          Value::String(v.to_string())); }
            let v = aws_str!(rp, "volumeId");          if !v.is_empty() { extensions.insert("aws_req_volume_id".into(),            Value::String(v.to_string())); }
            let v = aws_str!(rp, "allocationId");      if !v.is_empty() { extensions.insert("aws_req_allocation_id".into(),        Value::String(v.to_string())); }
        }

        // responseElements sub-fields (EC2 resource creation / modification results)
        if let Some(re) = aws.get("responseElements").and_then(Value::as_object) {
            let v = aws_str!(re, "publicIp");          if !v.is_empty() { extensions.insert("aws_res_public_ip".into(),              Value::String(v.to_string())); }
            let v = aws_str!(re, "networkInterfaceId"); if !v.is_empty() { extensions.insert("aws_res_network_interface_id".into(),  Value::String(v.to_string())); }
            let v = aws_str!(re, "allocationId");      if !v.is_empty() { extensions.insert("aws_res_allocation_id".into(),         Value::String(v.to_string())); }
            let v = aws_str!(re, "snapshotId");        if !v.is_empty() { extensions.insert("aws_res_snapshot_id".into(),           Value::String(v.to_string())); }
            let v = aws_str!(re, "volumeId");          if !v.is_empty() { extensions.insert("aws_res_volume_id".into(),             Value::String(v.to_string())); }
        }

        // serviceEventDetails sub-fields
        if let Some(sed) = aws.get("serviceEventDetails").and_then(Value::as_object) {
            macro_rules! sed_ext {
                ($key:expr, $ext:expr) => {
                    let _v = aws_str!(sed, $key);
                    if !_v.is_empty() { extensions.insert($ext.into(), Value::String(_v.to_string())); }
                };
            }
            sed_ext!("state",                  "aws_service_state");
            sed_ext!("CredentialChallenge",    "aws_credential_challenge");
            sed_ext!("CredentialVerification", "aws_credential_verification");
            sed_ext!("backupVaultName",        "aws_backup_vault_name");
            sed_ext!("resourceType",           "aws_service_resource_type");
        }

        // log_info sub-fields (S3 source file for batch-ingested CloudTrail logs)
        if let Some(li) = aws.get("log_info").and_then(Value::as_object) {
            let v = aws_str!(li, "log_file"); if !v.is_empty() { extensions.insert("aws_log_file".into(),     Value::String(v.to_string())); }
            let v = aws_str!(li, "s3bucket"); if !v.is_empty() { extensions.insert("aws_log_s3bucket".into(), Value::String(v.to_string())); }
        }

        // ── Per-source handling (severity overrides, extensions, source-specific typed columns) ──
        // The aws.source field identifies the Wazuh integration sub-type.
        let aws_source = aws_str!(aws, "source");
        match aws_source {

            // ── GuardDuty / Inspector / Macie ─────────────────────────────────────────
            // These are finding-type sources: severity comes from the finding metadata,
            // not from the Wazuh rule level.
            "guardduty" | "inspector" | "macie" => {
                // rule_name from finding title
                if rule_name.is_empty() {
                    let v = aws_str!(aws, "title");
                    if !v.is_empty() { rule_name = v.to_string(); }
                }
                // app_category from finding type
                if app_category.is_empty() {
                    let v = aws_str!(aws, "type");
                    if !v.is_empty() { app_category = v.to_string(); }
                }
                // domain from accountId (GuardDuty/Macie use camelCase; differs from aws_account_id)
                if domain.is_empty() {
                    let v = aws_str!(aws, "accountId");
                    if !v.is_empty() { domain = v.to_string(); }
                }

                // GuardDuty: actionType from service.action sub-object
                if action.is_empty() {
                    if let Some(svc) = aws.get("service").and_then(Value::as_object) {
                        if let Some(act_obj) = svc.get("action").and_then(Value::as_object) {
                            let v = act_obj.get("actionType").and_then(Value::as_str).unwrap_or("");
                            if !v.is_empty() { action = v.to_string(); }
                        }
                    }
                }

                // Severity override ─ GuardDuty uses a 0.0–9.9 float;
                // Inspector / Macie use strings (High/Medium/Low/Informational).
                if aws_source == "guardduty" {
                    let gd_sev_str = aws_str!(aws, "severity");
                    if !gd_sev_str.is_empty() {
                        let gd: f32 = gd_sev_str.parse().unwrap_or(0.0);
                        let (vid, vlabel) = match (gd * 10.0) as u32 {
                            80..=u32::MAX  => (5u8, "Critical"),
                            70..=79        => (4u8, "High"),
                            40..=69        => (3u8, "Medium"),
                            10..=39        => (2u8, "Low"),
                            _              => (1u8, "Informational"),
                        };
                        sev_id    = vid;
                        sev_label = vlabel.to_string();
                    }
                } else {
                    // Inspector / Macie severity as string label (from aws.severity or aws.severity.description)
                    let sev_raw = if let Some(sev_obj) = aws.get("severity").and_then(Value::as_object) {
                        sev_obj.get("description").and_then(Value::as_str).unwrap_or("").to_string()
                    } else {
                        aws_str!(aws, "severity").to_string()
                    };
                    if !sev_raw.is_empty() {
                        let (vid, vlabel) = match sev_raw.to_ascii_lowercase().as_str() {
                            "critical"                         => (5u8, "Critical"),
                            "high"                             => (4u8, "High"),
                            "medium" | "moderate"              => (3u8, "Medium"),
                            "low"                              => (2u8, "Low"),
                            "informational" | "info" | "none"  => (1u8, "Informational"),
                            _                                  => (sev_id, sev_label.as_str()),
                        };
                        sev_id    = vid;
                        sev_label = vlabel.to_string();
                    }
                }

                // Inspector hostname from assetAttributes (already in SRC_HOSTNAME paths,
                // but direct extraction is more reliable for the nested object)
                if src_hostname.is_empty() {
                    if let Some(aa) = aws.get("assetAttributes").and_then(Value::as_object) {
                        let v = aa.get("hostname").and_then(Value::as_str).unwrap_or("");
                        if !v.is_empty() { src_hostname = v.to_string(); }
                    }
                }

                // Finding identity extensions
                aws_ext!("arn",          "aws_finding_arn");
                aws_ext!("id",           "aws_finding_id");
                aws_ext!("description",  "aws_description");
                aws_ext!("region",       "aws_region_src");
                aws_ext!("createdAt",    "aws_created_at");
                aws_ext!("updatedAt",    "aws_updated_at");
            },

            // ── VPC Flow Logs ──────────────────────────────────────────────────────────
            // IP/port/protocol/action/bytes are already covered by field_paths entries
            // (aws.srcaddr, aws.dstaddr, aws.srcport, aws.dstport, aws.protocol,
            //  aws.action, aws.bytes).  Only extensions need explicit handling here.
            "vpc" => {
                // network_protocol: VPC encodes protocol as an IANA number string (6=TCP, 17=UDP, …)
                // or as a name; convert common numbers to names for readability.
                if !network_protocol.is_empty() {
                    let proto_norm = match network_protocol.trim() {
                        "6"   => "tcp",
                        "17"  => "udp",
                        "1"   => "icmp",
                        "58"  => "icmpv6",
                        "47"  => "gre",
                        "50"  => "esp",
                        other => other,
                    };
                    network_protocol = proto_norm.to_string();
                }
                // Extensions
                aws_ext!("interface_id", "aws_interface_id");
                aws_ext!("account_id",   "aws_flow_account_id");   // VPC uses underscored account_id
                aws_ext!("log_status",   "aws_log_status");
                aws_ext!("packets",      "aws_packets");
                aws_ext!("version",      "aws_flow_version");
            },

            // ── AWS WAF ────────────────────────────────────────────────────────────────
            "waf" => {
                // rule_name from terminatingRuleId
                if rule_name.is_empty() {
                    let v = aws_str!(aws, "terminatingRuleId");
                    if !v.is_empty() { rule_name = v.to_string(); }
                }
                // Extensions
                aws_ext!("webaclId",          "aws_waf_acl_id");
                aws_ext!("terminatingRuleId",  "aws_waf_rule_id");
                aws_ext!("terminatingRuleType","aws_waf_rule_type");
            },

            // ── AWS ALB (Application Load Balancer) ────────────────────────────────────
            "alb" => {
                // action_executed is ALB's way of reporting the routing decision
                if action.is_empty() {
                    let v = aws_str!(aws, "action_executed");
                    if !v.is_empty() { action = v.to_string(); }
                }
                // Extensions
                aws_ext!("error_reason",  "aws_alb_error_reason");
                aws_ext!("elb",           "aws_alb_name");
                aws_ext!("user_agent",    "aws_user_agent");
                aws_ext!("target_port",   "aws_alb_target_port");
                aws_ext!("target_status_code", "aws_alb_target_status");
            },

            // ── AWS S3 Server Access Logs ──────────────────────────────────────────────
            "s3_server_access" => {
                // domain = S3 bucket name
                if domain.is_empty() {
                    let v = aws_str!(aws, "bucket");
                    if !v.is_empty() { domain = v.to_string(); }
                }
                // status = Failure when an error_code is present (non-empty, non-dash)
                {
                    let v = aws_str!(aws, "error_code");
                    if !v.is_empty() && v != "-" {
                        if status.is_empty() { status = "Failure".to_string(); }
                        extensions.insert("aws_s3_error_code".into(), Value::String(v.to_string()));
                    }
                }
                // Extensions
                aws_ext!("user_agent",        "aws_user_agent");
                aws_ext!("key",               "aws_s3_key");
                aws_ext!("bytes_sent",        "aws_s3_bytes_sent");
                aws_ext!("object_size",       "aws_s3_object_size");
                aws_ext!("total_time",        "aws_s3_total_time_ms");
                aws_ext!("turn_around_time",  "aws_s3_turnaround_ms");
                aws_ext!("referrer",          "aws_s3_referrer");
            },

            // ── AWS Config ─────────────────────────────────────────────────────────────
            "config" => {
                // domain = awsAccountId (Config uses camelCase, different from CloudTrail aws_account_id)
                if domain.is_empty() {
                    let v = aws_str!(aws, "awsAccountId");
                    if !v.is_empty() { domain = v.to_string(); }
                }
                // rule_name = resourceId (the specific resource being audited)
                if rule_name.is_empty() {
                    let v = aws_str!(aws, "resourceId");
                    if !v.is_empty() { rule_name = v.to_string(); }
                }
                // Extensions
                aws_ext!("resourceName",                 "aws_resource_name");
                aws_ext!("configurationItemCaptureTime", "aws_config_capture_time");
                aws_ext!("configuration.complianceType", "aws_compliance_type");
                {
                    let v = aws_str!(aws, "configuration.configRuleList.configRuleName");
                    if !v.is_empty() { extensions.insert("aws_config_rule_name".into(), Value::String(v.to_string())); }
                }
            },

            // ── AWS Trusted Advisor ────────────────────────────────────────────────────
            "trustedadvisor" => {
                aws_ext!("uuid",         "aws_trusted_advisor_uuid");
                aws_ext!("category",     "aws_trusted_advisor_category");
                // status and rule_name already covered by STATUS/RULE_NAME field_paths
                // (aws.status, aws.check-name)
            },

            // ── AWS Inspector v2 (Security Hub-based) ────────────────────────────────
            "inspector2" => {
                aws_ext!("packageVulnerabilityDetails.vulnerabilityId", "aws_v2_cve_id");
                aws_ext!("severity.label",                               "aws_v2_severity_label");
                aws_ext!("type",                                         "aws_v2_finding_type");
            },

            // ── AWS Security Hub findings ──────────────────────────────────────────────
            "securityhub" => {
                if rule_name.is_empty() {
                    let v = aws_str!(aws, "Title");
                    if !v.is_empty() { rule_name = v.to_string(); }
                }
                if app_category.is_empty() {
                    let v = aws_str!(aws, "Type");
                    if !v.is_empty() { app_category = v.to_string(); }
                }
                // Severity label (CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL)
                {
                    let sev_raw = if let Some(sev_obj) = aws.get("Severity").and_then(Value::as_object) {
                        sev_obj.get("Label").and_then(Value::as_str).unwrap_or("").to_string()
                    } else {
                        String::new()
                    };
                    if !sev_raw.is_empty() {
                        let (vid, vlabel) = match sev_raw.to_ascii_lowercase().as_str() {
                            "critical"      => (5u8, "Critical"),
                            "high"          => (4u8, "High"),
                            "medium"        => (3u8, "Medium"),
                            "low"           => (2u8, "Low"),
                            "informational" => (1u8, "Informational"),
                            _               => (sev_id, sev_label.as_str()),
                        };
                        sev_id    = vid;
                        sev_label = vlabel.to_string();
                    }
                }
                aws_ext!("Id",               "aws_sh_finding_id");
                aws_ext!("ProductArn",        "aws_sh_product_arn");
                aws_ext!("GeneratorId",       "aws_sh_generator_id");
                aws_ext!("Description",       "aws_description");
                aws_ext!("RecordState",       "aws_sh_record_state");
                aws_ext!("WorkflowStatus",    "aws_sh_workflow_status");
            },

            // ── AWS KMS (mostly handled already via CloudTrail block above) ────────────
            // All KMS events are CloudTrail records; aws.source = "kms" is set by Wazuh
            // rules but the data structure is identical to cloudtrail.  Nothing extra needed.
            "kms" => {},

            _ => {},
        }
    }

    // ── Office 365 Unified Audit Log (data.office365.*) ──────────────────
    // Natively extracted — no field_mappings.toml entry required.
    // Covers events forwarded via Wazuh's office365 decoder
    // (integration = "office365", workloads: SharePoint, Exchange, Teams, AAD, …).
    if let Some(o365) = data_val.get("office365").and_then(Value::as_object) {
        macro_rules! o365_str {
            ($key:expr) => {
                o365.get($key).and_then(Value::as_str).unwrap_or("")
            };
        }
        macro_rules! o365_ext {
            ($key:expr, $ext:expr) => {
                let _v = o365_str!($key);
                if !_v.is_empty() { extensions.insert($ext.into(), Value::String(_v.to_string())); }
            };
        }

        // src_ip: ClientIPAddress (capital 'A' variant not covered by field_paths SRC_IP)
        if src_ip.is_empty() {
            let v = o365_str!("ClientIPAddress");
            if !v.is_empty() { src_ip = v.to_string(); }
        }

        // actor_user: Actor array entry with Type=5 holds the UPN (user principal name)
        if actor_user.is_empty() {
            if let Some(actors) = o365.get("Actor").and_then(Value::as_array) {
                for item in actors {
                    if item.get("Type").and_then(Value::as_str) == Some("5") {
                        if let Some(id) = item.get("ID").and_then(Value::as_str) {
                            if !id.is_empty() { actor_user = id.to_string(); break; }
                        }
                    }
                }
            }
        }

        // app_name: Workload → ApplicationDisplayName → AppAccessContext.ClientAppName
        if app_name.is_empty() {
            let v = o365_str!("Workload");
            if !v.is_empty() { app_name = v.to_string(); }
        }
        if app_name.is_empty() {
            let v = o365_str!("ApplicationDisplayName");
            if !v.is_empty() { app_name = v.to_string(); }
        }
        if app_name.is_empty() {
            if let Some(aac) = o365.get("AppAccessContext").and_then(Value::as_object) {
                let v = aac.get("ClientAppName").and_then(Value::as_str).unwrap_or("");
                if !v.is_empty() { app_name = v.to_string(); }
            }
        }

        // domain: OrganizationId (AAD tenant GUID)
        if domain.is_empty() {
            let v = o365_str!("OrganizationId");
            if !v.is_empty() { domain = v.to_string(); }
        }

        // action: Operation (UserLoggedIn, FileUploaded, SendMessage, SetMailboxPermission, …)
        if action.is_empty() {
            let v = o365_str!("Operation");
            if !v.is_empty() { action = v.to_string(); }
        }

        // status: ResultStatus (Succeeded / Failed / PartiallySucceeded / True / False)
        if status.is_empty() {
            let v = o365_str!("ResultStatus");
            if !v.is_empty() { status = v.to_string(); }
        }

        // Extension metadata — identifiers, session, app context
        o365_ext!("AadAppId",               "o365_aad_app_id");
        o365_ext!("ActorAppId",             "o365_actor_app_id");
        o365_ext!("ActorContextId",         "o365_actor_context_id");
        o365_ext!("ActorInfoString",        "o365_actor_info");
        o365_ext!("AddOnGuid",              "o365_addon_guid");
        o365_ext!("AppId",                  "o365_app_id");
        o365_ext!("AppIdentity",            "o365_app_identity");
        o365_ext!("ApplicationId",          "o365_application_id");
        o365_ext!("AssertingApplicationId", "o365_asserting_app_id");
        o365_ext!("AuthType",               "o365_auth_type");
        o365_ext!("AuthenticationType",     "o365_authentication_type");
        o365_ext!("AzureActiveDirectoryEventType", "o365_aad_event_type");
        o365_ext!("BrowserName",            "browser_name");
        o365_ext!("BrowserVersion",         "browser_version");
        o365_ext!("CallId",                 "o365_call_id");
        o365_ext!("ChatName",               "o365_chat_name");
        o365_ext!("ChatThreadId",           "o365_chat_thread_id");
        o365_ext!("ClientAppId",            "o365_client_app_id");
        o365_ext!("ClientApplication",      "o365_client_application");
        o365_ext!("ClientInfoString",       "o365_client_info");
        o365_ext!("ClientRegion",           "o365_client_region");
        o365_ext!("ClientRequestId",        "o365_client_request_id");
        o365_ext!("UserType",               "o365_user_type");
        o365_ext!("RecordType",             "o365_record_type");
        o365_ext!("AgentId",                "o365_agent_id");
        o365_ext!("AgentName",              "o365_agent_name");

        // AppAccessContext sub-object — OAuth session / token metadata
        if let Some(aac) = o365.get("AppAccessContext").and_then(Value::as_object) {
            macro_rules! aac_ext {
                ($key:expr, $ext:expr) => {
                    let _v = aac.get($key).and_then(Value::as_str).unwrap_or("");
                    if !_v.is_empty() { extensions.insert($ext.into(), Value::String(_v.to_string())); }
                };
            }
            aac_ext!("AADSessionId",   "o365_aad_session_id");
            aac_ext!("CorrelationId",  "o365_correlation_id");
            aac_ext!("UniqueTokenId",  "o365_token_id");
            aac_ext!("UserObjectId",   "o365_user_object_id");
            aac_ext!("DeviceId",       "o365_device_id");
            aac_ext!("ClientAppId",    "o365_aac_client_app_id");
            aac_ext!("ClientAppName",  "o365_aac_client_app_name");
        }
    }

    // ── GCP Cloud Logging (data.gcp.*) ───────────────────────────────────
    // Covers: Audit logs (protoPayload), DNS (jsonPayload), Security Command Center.
    // Severity from gcp.severity overrides the Wazuh rule level — GCP has its own
    // scale: DEBUG < INFO < NOTICE < WARNING < ERROR < CRITICAL < ALERT < EMERGENCY.
    if let Some(gcp) = data_val.get("gcp").and_then(Value::as_object) {
        macro_rules! gcp_str { ($k:expr) => { gcp.get($k).and_then(Value::as_str).unwrap_or("") }; }
        macro_rules! gcp_ext {
            ($k:expr, $ext:expr) => {
                let _v = gcp_str!($k);
                if !_v.is_empty() { extensions.insert($ext.into(), Value::String(_v.to_string())); }
            };
        }

        // Severity override — GCP severity is more precise than Wazuh rule level.
        let gcp_sev = gcp_str!("severity");
        if !gcp_sev.is_empty() {
            let (vid, vlabel) = match gcp_sev.to_ascii_uppercase().as_str() {
                "EMERGENCY" | "ALERT"  => (5u8, "Critical"),
                "CRITICAL"             => (5u8, "Critical"),
                "ERROR"                => (4u8, "High"),
                "WARNING"              => (3u8, "Medium"),
                "NOTICE"               => (2u8, "Low"),
                "INFO" | "DEBUG"       => (1u8, "Informational"),
                _                      => (sev_id, sev_label.as_str()),
            };
            sev_id    = vid;
            sev_label = vlabel.to_string();
        }

        // Typed columns from protoPayload (Audit logs)
        if let Some(pp) = gcp.get("protoPayload").and_then(Value::as_object) {
            if actor_user.is_empty() {
                let v = pp.get("authenticationInfo")
                    .and_then(Value::as_object)
                    .and_then(|a| a.get("principalEmail"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if !v.is_empty() { actor_user = v.to_string(); }
            }
            if src_ip.is_empty() {
                let v = pp.get("requestMetadata")
                    .and_then(Value::as_object)
                    .and_then(|rm| rm.get("callerIp"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if !v.is_empty() { src_ip = v.to_string(); }
            }
            if action.is_empty() {
                let v = pp.get("methodName").and_then(Value::as_str).unwrap_or("");
                if !v.is_empty() { action = v.to_string(); }
            }
            if url.is_empty() {
                let v = pp.get("resourceName").and_then(Value::as_str).unwrap_or("");
                if !v.is_empty() { url = v.to_string(); }
            }
        }

        // Typed columns from jsonPayload (DNS, VPC Flow, Cloud Armor, etc.)
        if let Some(jp) = gcp.get("jsonPayload").and_then(Value::as_object) {
            if src_ip.is_empty() {
                let v = jp.get("sourceIP").and_then(Value::as_str).unwrap_or("");
                if !v.is_empty() { src_ip = v.to_string(); }
            }
        }

        // resource.labels.project_id → domain (GCP project = organizational boundary)
        if domain.is_empty() {
            if let Some(rl) = gcp.get("resource")
                .and_then(Value::as_object)
                .and_then(|r| r.get("labels"))
                .and_then(Value::as_object)
            {
                let v = rl.get("project_id").and_then(Value::as_str).unwrap_or("");
                if !v.is_empty() { domain = v.to_string(); }
            }
        }

        // Extensions
        gcp_ext!("s_request_id",  "gcp_request_id");
        gcp_ext!("insertId",      "gcp_insert_id");
        gcp_ext!("logName",       "gcp_log_name");
    }

    // ── Docker Integration (data.docker.*) ───────────────────────────────
    // Wazuh docker decoder produces docker.Action, docker.Type, docker.status,
    // docker.level, and docker.Actor.* from Docker daemon events.
    if let Some(docker) = data_val.get("docker").and_then(Value::as_object) {
        macro_rules! dk_str { ($k:expr) => { docker.get($k).and_then(Value::as_str).unwrap_or("") }; }

        // docker.level (info/warning/error) → severity override
        let dk_level = dk_str!("level");
        if !dk_level.is_empty() {
            let (vid, vlabel) = match dk_level.to_ascii_lowercase().as_str() {
                "error"   => (4u8, "High"),
                "warning" | "warn" => (3u8, "Medium"),
                _         => (1u8, "Informational"),
            };
            if sev_id < vid { sev_id = vid; sev_label = vlabel.to_string(); }
        }

        // docker.Action → action (create/start/stop/destroy/exec_start/…)
        if action.is_empty() {
            let v = dk_str!("Action");
            if !v.is_empty() { action = v.to_string(); }
        }

        // docker.Type → app_category (container/network/volume/plugin/secret)
        if app_category.is_empty() {
            let v = dk_str!("Type");
            if !v.is_empty() { app_category = v.to_string(); }
        }

        // docker.Actor.Attributes.name → app_name (container name)
        if app_name.is_empty() {
            if let Some(actor) = docker.get("Actor").and_then(Value::as_object) {
                let v = actor.get("Attributes")
                    .and_then(Value::as_object)
                    .and_then(|a| a.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if !v.is_empty() { app_name = v.to_string(); }
            }
        }

        // Role-change extensions (docker.Actor.Attributes.role.new / role.old)
        if let Some(attr) = docker.get("Actor")
            .and_then(Value::as_object)
            .and_then(|a| a.get("Attributes"))
            .and_then(Value::as_object)
        {
            if let Some(v) = attr.get("role.new").and_then(Value::as_str) {
                if !v.is_empty() { extensions.insert("docker_role_new".into(), Value::String(v.to_string())); }
            }
            if let Some(v) = attr.get("role.old").and_then(Value::as_str) {
                if !v.is_empty() { extensions.insert("docker_role_old".into(), Value::String(v.to_string())); }
            }
            if let Some(v) = attr.get("image").and_then(Value::as_str) {
                if !v.is_empty() { extensions.insert("docker_image".into(), Value::String(v.to_string())); }
            }
        }
    }

    // ── MS Graph Security (data.ms-graph.*) ──────────────────────────────
    // Microsoft 365 Defender / Sentinel alerts forwarded via Wazuh ms-graph integration.
    if let Some(msg) = data_val.get("ms-graph").and_then(Value::as_object) {
        macro_rules! msg_str { ($k:expr) => { msg.get($k).and_then(Value::as_str).unwrap_or("") }; }
        macro_rules! msg_ext {
            ($k:expr, $ext:expr) => {
                let _v = msg_str!($k);
                if !_v.is_empty() { extensions.insert($ext.into(), Value::String(_v.to_string())); }
            };
        }

        // Severity override — MS Graph uses string labels
        {
            let ms_sev = msg_str!("severity");
            if !ms_sev.is_empty() {
                let (vid, vlabel) = match ms_sev.to_ascii_lowercase().as_str() {
                    "high"          => (4u8, "High"),
                    "medium"        => (3u8, "Medium"),
                    "low"           => (2u8, "Low"),
                    "informational" => (1u8, "Informational"),
                    _               => (sev_id, sev_label.as_str()),
                };
                sev_id    = vid;
                sev_label = vlabel.to_string();
            }
        }

        // Typed column fills
        if rule_name.is_empty() {
            let v = msg_str!("title");
            if !v.is_empty() { rule_name = v.to_string(); }
        }
        if app_category.is_empty() {
            let v = msg_str!("category");
            if !v.is_empty() { app_category = v.to_string(); }
        }
        if status.is_empty() {
            let v = msg_str!("status");
            if !v.is_empty() { status = v.to_string(); }
        }
        if app_name.is_empty() {
            // Take whichever is non-empty: detectionSource > serviceSource
            let v = msg_str!("detectionSource");
            let v = if v.is_empty() { msg_str!("serviceSource") } else { v };
            if !v.is_empty() { app_name = v.to_string(); }
        }
        if dst_hostname.is_empty() {
            let v = msg_str!("resource");
            if !v.is_empty() { dst_hostname = v.to_string(); }
        }

        // Extensions
        msg_ext!("id",              "ms_graph_alert_id");
        msg_ext!("incidentId",      "ms_graph_incident_id");
        msg_ext!("classification",  "ms_graph_classification");
        msg_ext!("determination",   "ms_graph_determination");
        msg_ext!("relationship",    "ms_graph_relationship");
        msg_ext!("detectionSource", "ms_graph_detection_source");
        msg_ext!("serviceSource",   "ms_graph_service_source");
        msg_ext!("tenantId",        "ms_graph_tenant_id");
    }

    if !custom.field_map.is_empty() {
        for (wazuh_field, ocsf_target) in &custom.field_map {
            let val = get_data_field(&data_val, wazuh_field.as_str());
            if val.is_empty() { continue; }
            match ocsf_target.as_str() {
                "src_ip"           => { if src_ip.is_empty()           { src_ip           = val; } }
                "dst_ip"           => { if dst_ip.is_empty()           { dst_ip           = val; } }
                "src_port"         => { if src_port == 0   { src_port   = val.parse().unwrap_or(0); } }
                "dst_port"         => { if dst_port == 0   { dst_port   = val.parse().unwrap_or(0); } }
                "actor_user"       => { if actor_user.is_empty()       { actor_user       = val; } }
                "target_user"      => { if target_user.is_empty()      { target_user      = val; } }
                "domain"           => { if domain.is_empty()           { domain           = val; } }
                "url"              => { if url.is_empty()              { url              = val; } }
                "http_method"      => { if http_method.is_empty()      { http_method      = val; } }
                "http_status"      => { if http_status == 0 { http_status = val.parse().unwrap_or(0); } }
                "app_name"         => { if app_name.is_empty()         { app_name         = val; } }
                "src_hostname"     => { if src_hostname.is_empty()     { src_hostname     = val; } }
                "file_name"        => { if file_name.is_empty()        { file_name        = val; } }
                "process_name"     => { if process_name.is_empty()     { process_name     = val; } }
                "process_id"       => { if process_id == 0  { process_id  = val.parse().unwrap_or(0); } }
                "rule_name"        => { if rule_name.is_empty()        { rule_name        = val; } }
                "category"         => { if app_category.is_empty()     { app_category     = val; } }
                "action"           => { if action.is_empty()           { action           = val; } }
                "status"           => { if status.is_empty()           { status           = val; } }
                "nat_src_ip"       => { if nat_src_ip.is_empty()       { nat_src_ip       = val; } }
                "nat_dst_ip"       => { if nat_dst_ip.is_empty()       { nat_dst_ip       = val; } }
                "nat_src_port"     => { if nat_src_port == 0 { nat_src_port = val.parse().unwrap_or(0); } }
                "nat_dst_port"     => { if nat_dst_port == 0 { nat_dst_port = val.parse().unwrap_or(0); } }
                "dst_hostname"     => { if dst_hostname.is_empty()     { dst_hostname     = val; } }
                "interface_in"     => { if interface_in.is_empty()     { interface_in     = val; } }
                "interface_out"    => { if interface_out.is_empty()    { interface_out    = val; } }
                "bytes_in"         => { if bytes_in == 0   { bytes_in   = val.parse().unwrap_or(0); } }
                "bytes_out"        => { if bytes_out == 0  { bytes_out  = val.parse().unwrap_or(0); } }
                "network_protocol" => { if network_protocol.is_empty() { network_protocol = val; } }
                other              => { extensions.insert(other.to_string(), Value::String(val)); }
            }
        }
    }
    let extensions_json =
        serde_json::to_string(&extensions).unwrap_or_else(|_| "{}".into());

    // ── Full data sub-object (lossless) ───────────────────────────────────
    let event_data = serde_json::to_string(&data_val)
        .unwrap_or_else(|_| "{}".into());

    // ── Unmapped top-level keys ───────────────────────────────────────────
    const KNOWN: &[&str] = &[
        "@timestamp", "timestamp", "agent", "rule", "manager",
        "location", "data", "id", "decoder",
        // Standard Wazuh top-level sections handled natively above:
        "syscheck",        // FIM — path/hashes extracted to file_name + extensions
        "full_log",        // Raw log text — already in raw_data
        "predecoder",      // Pre-decoder fields extracted to src_hostname/app_name
        "previous_log",    // Previous log entry (diff context)
        "previous_output", // Previous alert output (diff context)
    ];
    let unmapped_obj: Map<String, Value> = obj.iter()
        .filter(|(k, _)| !KNOWN.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let unmapped = serde_json::to_string(&unmapped_obj)
        .unwrap_or_else(|_| "{}".into());

    // ── Route ─────────────────────────────────────────────────────────────
    let table = routing_table(db, &agent_name, location, special_locs);

    let ocsf_cls = classify_event(&rule_groups, &decoder_name, location);

    // ── Backfill status string from rule groups (auth/network events) ───────
    // Wazuh encodes success/failure in rule.groups, not in data.status, so we
    // must check groups before computing status_id.
    if status.is_empty() {
        if rule_groups.iter().any(|&g| matches!(g,
            "authentication_success" | "win_authentication_success" |
            "pam_success" | "sudo"
        )) {
            status = "Success".to_string();
        } else if rule_groups.iter().any(|&g| matches!(g,
            "authentication_failed" | "authentication_failure" |
            "win_authentication_failed" | "pam_failure" |
            "invalid_login" | "multiple_authentication_failures"
        )) {
            status = "Failure".to_string();
        }
    }
    // For firewall/network events: derive status string from action when absent
    if status.is_empty() && ocsf_cls.class_uid == 4001 && !action.is_empty() {
        status = action.clone();
    }

    // ── Override severity for vulnerability findings (class 2002) ─────────
    // Scanner label (Low/Medium/High/Critical) is more accurate than rule level.
    if ocsf_cls.class_uid == 2002 && !vuln_sev.is_empty() {
        let (vid, vlabel) = match vuln_sev.to_ascii_lowercase().as_str() {
            "critical"                         => (5u8, "Critical"),
            "high"                             => (4u8, "High"),
            "medium" | "moderate"              => (3u8, "Medium"),
            "low"                              => (2u8, "Low"),
            "informational" | "info" | "none"  => (1u8, "Informational"),
            _                                  => (sev_id, sev_label.as_str()),
        };
        sev_id    = vid;
        sev_label = vlabel.to_string();
    }

    // ── Activity (class-aware per OCSF 1.7.0) ────────────────────────────
    let grp = |s: &str| rule_groups.contains(&s);
    let (activity_id, activity_name): (u8, &str) = match ocsf_cls.class_uid {

        // 1001 File System Activity: Create/Read/Update/Delete/Rename/Other
        1001 => match syscheck_event.to_ascii_lowercase().as_str() {
            "modified" | "changed"           => (3, "Update"),
            "deleted"  | "removed"           => (4, "Delete"),
            "renamed"  | "moved"             => (5, "Rename"),
            _                                => (1, "Create"),
        },

        // 1006 Process Activity: Launch/Terminate/Open/Other
        1006 => {
            if grp("process_stopped") || grp("process_terminated")
                || grp("sysmon_process_terminate")
            { (2, "Terminate") } else { (1, "Launch") }
        },

        // 3001 Account Change
        3001 => {
            if      grp("userdel")                            { (2, "Delete User")      }
            else if grp("groupdel")                           { (8, "Delete Group")     }
            else if grp("addgroup")                           { (7, "Create Group")     }
            else if grp("groupmod")                           { (9, "Update Group")     }
            else if grp("usermod") || grp("account_changed") { (3, "Update User")      }
            else if grp("passwd")  || grp("password_changed"){ (12,"Change Password")  }
            else                                              { (1, "Create User")      }
        },

        // 3002 Authentication: Logon/Logoff/Other
        3002 => {
            if grp("logoff") || grp("logout") { (2, "Logoff") }
            else { (1, "Logon") }
        },

        // 4001 Network Activity: Open/Close/Reset/Fail/Refuse/Traffic
        4001 => match action.to_ascii_lowercase().as_str() {
            "allow" | "allowed" | "permit" | "pass"   |
            "accept" | "accepted" | "open"             => (1, "Open"),
            "deny"   | "denied"  | "block" | "blocked" |
            "drop"   | "dropped" | "reject" | "rejected" |
            "refuse" | "refused"                       => (5, "Refuse"),
            "close"  | "closed"  | "end"   | "finish"  |
            "finished" | "timeout" | "timed_out"       => (2, "Close"),
            "reset"  | "rst"                           => (3, "Reset"),
            "fail"   | "failed"  | "error"             => (4, "Fail"),
            _                                          => (6, "Traffic"),
        },

        // 4002 HTTP Activity: Get/Put/Post/Delete/Connect/Options/Head
        4002 => match http_method.to_ascii_lowercase().as_str() {
            "get"     => (1, "Get"),
            "put"     => (2, "Put"),
            "post"    => (3, "Post"),
            "delete"  => (4, "Delete"),
            "connect" => (5, "Connect"),
            "options" => (6, "Options"),
            "head"    => (7, "Head"),
            _         => (99, "Other"),
        },

        // 4003 DNS Activity: Query/Response/Traffic
        // Zeek dns.log + most DNS decoders set action="response" or group "dns_response"
        // when the event represents a server answer; otherwise treat as a query.
        4003 => {
            let a = action.to_ascii_lowercase();
            if grp("dns_response") || a.contains("response") || a.contains("answer") {
                (2, "Response")
            } else if grp("dns_traffic") || a == "traffic" {
                (3, "Traffic")
            } else {
                (1, "Query")
            }
        },

        // 4004 DHCP Activity: Assign/Renew/Release/Error
        // Wazuh dhcpd decoder exposes the DHCP message type via the ACTION field paths.
        // DHCPREQUEST(w/ renewing/rebinding) → Renew; DHCPRELEASE → Release; DHCPNAK → Error; else Assign.
        4004 => {
            let a = action.to_ascii_lowercase();
            if a.contains("release") || a == "dhcprelease" {
                (3, "Release")
            } else if a.contains("nak") || a.contains("nack") || a.contains("error") {
                (4, "Error")
            } else if a.contains("request") || a.contains("renew") || a.contains("rebind") {
                (2, "Renew")
            } else {
                (1, "Assign")
            }
        },

        // All other classes (2002/2003/2004/…): Create
        _ => (1, "Create"),
    };

    let type_uid: u32 = ocsf_cls.class_uid * 100 + activity_id as u32;

    let status_id: u8 = match ocsf_cls.class_uid {
        2002 | 2003 | 2004 => match status.to_ascii_lowercase().as_str() {
            "in_progress" | "in progress" | "investigating" => 2,
            "suppressed"  | "benign" | "false_positive"     => 3,
            "resolved"    | "closed" | "remediated"         => 4,
            "archived"                                      => 5,
            "deleted"                                       => 6,
            _                                               => 1,
        },
        // Authentication (3002): check backfilled status string (set above from rule.groups)
        3002 => match status.to_ascii_lowercase().as_str() {
            "success" | "allow" | "allowed" | "pass" | "passed" | "accepted" => 1,
            "failure" | "fail" | "failed" | "deny" | "denied"
                | "block" | "blocked" | "drop" | "dropped"
                | "reject" | "rejected" | "error" => 2,
            "" => 0,
            _  => 99,
        },
        _ => match status.to_ascii_lowercase().as_str() {
            "success" | "allow" | "allowed" | "pass" | "passed" | "accepted" => 1,
            "failure" | "fail" | "failed" | "deny" | "denied"
                | "block" | "blocked" | "drop" | "dropped"
                | "reject" | "rejected" => 2,
            "" => 0,
            _  => 99,
        },
    };

    let confidence_id: u8 = match rule_level {
        0      => 0,
        1..=6  => 1,
        7..=12 => 2,
        _      => 3,
    };

    debug!(
        agent   = %agent_name,
        rule    = %rule_id,
        class   = %ocsf_cls.class_name,
        sev_id  = sev_id,
        table   = %table,
        "transform ok"
    );

    track_unmapped_fields(&data_val, custom);

    let rec = OcsfRecord {
        time: time_secs,
        time_dt,
        ocsf_version:      custom.ocsf_version.clone(),
        class_uid:         ocsf_cls.class_uid,
        class_name:        ocsf_cls.class_name.into(),
        category_uid:      ocsf_cls.category_uid,
        category_name:     ocsf_cls.category_name.into(),
        severity_id:       sev_id,
        severity:          sev_label,
        activity_id,
        activity_name:     activity_name.into(),
        type_uid,
        status_id,
        confidence_id,
        status,
        action,
        device_uid:        agent_id,
        device_name:       agent_name,
        device_ip:         agent_ip,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        nat_src_ip,
        nat_dst_ip,
        nat_src_port,
        nat_dst_port,
        network_protocol,
        bytes_in,
        bytes_out,
        actor_user,
        target_user,
        domain,
        url,
        http_method,
        http_status,
        app_name,
        src_hostname,
        dst_hostname,
        file_name,
        process_name,
        process_id,
        interface_in,
        interface_out,
        rule_name,
        app_category,
        finding_title:     if finding_title_override.is_empty() { rule_desc } else { finding_title_override },
        finding_uid:       rule_id,
        finding_types,
        wazuh_rule_level:  rule_level as u8,
        wazuh_fired_times: rule_fired_times,
        pci_dss,
        gdpr,
        hipaa,
        nist_800_53,
        attack_technique:  json_arr("technique"),
        attack_id:         json_arr("id"),
        attack_tactic:     json_arr("tactic"),
        cve_id,
        cvss_score,
        src_location:      location.into(),
        decoder_name,
        manager_name,
        event_data,
        extensions:        extensions_json,
        unmapped,
        raw_data:          raw.to_string(),
    };

    check_and_warn(&rec);

    Some((table, rec))
}
