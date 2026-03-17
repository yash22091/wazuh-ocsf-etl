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

    // ── Custom mapping overlay ────────────────────────────────────────────
    // Only for site-specific decoder fields not handled above.
    let mut extensions: Map<String, Value> = Map::new();
    // Add win-specific context into extensions (win_event_id, win_channel, win_logon_type)
    { let v = jpath(&data_val, "win.system.eventID");         if !v.is_empty() { extensions.insert("win_event_id".into(),   Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "win.system.channel");         if !v.is_empty() { extensions.insert("win_channel".into(),    Value::String(v.to_string())); } }
    { let v = jpath(&data_val, "win.eventdata.logonType");    if !v.is_empty() { extensions.insert("win_logon_type".into(), Value::String(v.to_string())); } }
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
        finding_title:     rule_desc,
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
