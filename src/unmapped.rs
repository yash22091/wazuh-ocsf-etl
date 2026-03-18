use std::collections::{HashMap, HashSet};
use std::path::Path;

use chrono::Utc;
use once_cell::sync::Lazy;
use serde_json::Value;
use tracing::{info, warn};

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

    // ── Other generic decoder fields (natively extracted in transform.rs) ───
    for p in &["file", "title", "gid", "home", "shell", "id", "integration"] { s.insert(p); }

    // ── predecoder fields (natively extracted in transform.rs) ──────────────
    for p in &["predecoder.hostname", "predecoder.program_name", "predecoder.timestamp"] {
        s.insert(p);
    }

    // ── SCA (Security Configuration Assessment) native paths ──────────────
    for p in &[
        "sca.scan_id", "sca.policy", "sca.policy_id", "sca.description", "sca.file",
        "sca.score", "sca.total_checks", "sca.passed", "sca.failed", "sca.invalid",
        "sca.check.id", "sca.check.title", "sca.check.result", "sca.check.description",
        "sca.check.rationale", "sca.check.remediation", "sca.check.reason",
        "sca.check.references", "sca.check.command.0", "sca.check.file.0",
        "sca.check.compliance.cis", "sca.check.compliance.cis_csc",
        "sca.check.compliance.cis_csc_v7", "sca.check.compliance.cis_csc_v8",
        "sca.check.compliance.cmmc_v2.0",
        "sca.check.compliance.hipaa", "sca.check.compliance.iso_27001-2013",
        "sca.check.compliance.mitre_mitigations", "sca.check.compliance.mitre_tactics",
        "sca.check.compliance.mitre_techniques", "sca.check.compliance.nist_sp_800-53",
        "sca.check.compliance.pci_dss_v3.2.1", "sca.check.compliance.pci_dss_v4.0",
        "sca.check.compliance.soc_2",
    ] { s.insert(p); }

    // ── Linux audit AVC context (natively extracted in transform.rs) ────────
    for p in &[
        "audit.id", "audit.type", "audit.directory.name",
        "audit.euid", "audit.uid", "audit.gid", "audit.session",
    ] { s.insert(p); }

    // ── AWS CloudTrail / integrations (natively extracted in transform.rs) ──
    for p in &[
        // Top-level CloudTrail fields
        "aws.source_ip_address", "aws.sourceIPAddress",
        "aws.eventID", "aws.eventTime", "aws.eventType", "aws.eventCategory",
        "aws.eventVersion", "aws.requestID", "aws.awsRegion",
        "aws.userAgent", "aws.managementEvent", "aws.readOnly",
        "aws.recipientAccountId", "aws.sharedEventID",
        "aws.sessionCredentialFromConsole", "aws.source", "aws.errorMessage",
        "aws.aws_account_id",
        // userIdentity
        "aws.userIdentity.arn", "aws.userIdentity.type",
        "aws.userIdentity.invokedBy", "aws.userIdentity.accessKeyId",
        "aws.userIdentity.credentialId",
        "aws.userIdentity.sessionContext.attributes.creationDate",
        "aws.userIdentity.sessionContext.attributes.mfaAuthenticated",
        "aws.userIdentity.sessionContext.sessionIssuer.arn",
        "aws.userIdentity.sessionContext.sessionIssuer.accountId",
        "aws.userIdentity.sessionContext.sessionIssuer.principalId",
        "aws.userIdentity.sessionContext.sessionIssuer.type",
        "aws.userIdentity.sessionContext.webIdFederationData.federatedProvider",
        // additionalEventData
        "aws.additionalEventData.UserName", "aws.additionalEventData.LoginTo",
        "aws.additionalEventData.MFAUsed", "aws.additionalEventData.MFAIdentifier",
        "aws.additionalEventData.MobileVersion", "aws.additionalEventData.CredentialType",
        "aws.additionalEventData.AuthWorkflowID", "aws.additionalEventData.keyMaterialId",
        // tlsDetails
        "aws.tlsDetails.tlsVersion", "aws.tlsDetails.cipherSuite",
        "aws.tlsDetails.keyExchange", "aws.tlsDetails.clientProvidedHostHeader",
        // responseElements (typed columns + extensions)
        "aws.responseElements.ConsoleLogin", "aws.responseElements.status",
        "aws.responseElements.publicIp", "aws.responseElements.networkInterfaceId",
        "aws.responseElements.allocationId", "aws.responseElements.snapshotId",
        "aws.responseElements.volumeId",
        // requestParameters (extensions)
        "aws.requestParameters.keyId", "aws.requestParameters.networkInterfaceId",
        "aws.requestParameters.groupId", "aws.requestParameters.subnetId",
        "aws.requestParameters.snapshotId", "aws.requestParameters.volumeId",
        "aws.requestParameters.allocationId",
        // resources, log_info
        "aws.resources.ARN", "aws.resources.type", "aws.resources.accountId",
        "aws.log_info.log_file", "aws.log_info.s3bucket",
        // serviceEventDetails
        "aws.serviceEventDetails.UserAuthentication",
        "aws.serviceEventDetails.state",
        "aws.serviceEventDetails.CredentialChallenge",
        "aws.serviceEventDetails.CredentialVerification",
        "aws.serviceEventDetails.backupVaultName",
        "aws.serviceEventDetails.resourceType",
    ] { s.insert(p); }

    // ── AWS requestParameters / responseElements deep nested fields ──────────
    // These are EC2/CloudTrail API parameters that vary per-call.  They are
    // stored in the raw event and the simple ones are extracted above; the
    // remaining deeply-nested array items (tagSet, ipPermissions items, etc.)
    // are suppressed here to keep the unmapped report focused on actionable fields.
    s
});

/// Per-field stats accumulated at runtime.
#[derive(Debug, Default, Clone)]
pub(crate) struct FieldInfo {
    pub(crate) count:   u64,
    pub(crate) example: String,
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
        // Suppress deeply-nested AWS API parameters/response fields — these are
        // per-call EC2/service payloads (tag arrays, ipPermissions items, etc.)
        // that have no standard OCSF mapping and would flood the report.
        if path.starts_with("aws.requestParameters.") || path.starts_with("aws.responseElements.") {
            continue;
        }

        let entry = guard.entry(path.clone()).or_insert_with(|| FieldInfo {
            count:   0,
            example: example.clone(),
        });
        entry.count += 1;
        if !example.is_empty() {
            entry.example = example;
        }
    }
}

/// Archive the existing unmapped_fields report (if any) to a timestamped file
/// before the current session's in-memory tracker is reset on startup.
/// This preserves the previous run's discoveries so nothing is lost on restart.
pub(crate) fn archive_unmapped_report(path: &Path) {
    if !path.exists() { return; }
    let ts = Utc::now().format("%Y%m%dT%H%M%SZ");
    let archive = path.with_file_name(format!(
        "{}.{ts}.bak",
        path.file_stem().and_then(|s| s.to_str()).unwrap_or("unmapped_fields")
    ));
    if let Err(e) = std::fs::rename(path, &archive) {
        warn!("unmapped_fields: archive failed ({} → {}): {e}",
              path.display(), archive.display());
    } else {
        info!("unmapped_fields: previous report archived → {}", archive.display());
    }
}

/// Serialize UNMAPPED_TRACKER to `path` atomically (write temp → rename).
/// Only the sorted list of field names is written — count/example are omitted
/// to keep the file simple and scannable.
pub(crate) fn write_unmapped_report(path: &Path) {
    let guard = match UNMAPPED_TRACKER.lock() {
        Ok(g)  => g,
        Err(e) => e.into_inner(),
    };
    if guard.is_empty() { return; }

    // Sort by descending occurrence count so the most common unknowns appear first.
    let mut fields: Vec<(&String, &FieldInfo)> = guard.iter().collect();
    fields.sort_by(|a, b| b.1.count.cmp(&a.1.count).then(a.0.cmp(b.0)));

    let field_names: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();

    let doc = serde_json::json!({
        "note": "Fields from data.* that are not yet mapped to an OCSF typed column. \
                 Add entries to config/field_mappings.toml to promote them.",
        "fields": field_names,
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
