use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tracing::warn;

use crate::record::OcsfRecord;

// ─── OCSF 1.7.0 schema validator ─────────────────────────────────────────────
//
// Warn-only: violations are logged at WARN level but the event is ALWAYS
// forwarded to ClickHouse — no events are ever silently dropped.
//
// All checks are O(1) comparisons against compile-time constant slices.
// No heap allocation in the common (violation-free) path.
//
// Disable entirely with:  OCSF_VALIDATE=false  (e.g. during load testing)

pub(crate) static OCSF_VALIDATE: AtomicBool = AtomicBool::new(true);
pub(crate) static OCSF_VIOLATION_COUNT: AtomicU64 = AtomicU64::new(0);

const VALID_CLASS_UIDS: &[u32] = &[
    // Cat 1 — System Activity
    1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008,
    // Cat 2 — Findings
    2001, 2002, 2003, 2004, 2005, 2006,
    // Cat 3 — Identity & Access Management
    3001, 3002, 3003, 3004, 3005, 3006,
    // Cat 4 — Network Activity
    4001, 4002, 4003, 4004, 4005, 4006, 4007,
    // Cat 5 — Discovery
    5001, 5002, 5003, 5004,
    // Cat 6 — Application Activity
    6001, 6002, 6003, 6004, 6005,
];

const VALID_SEVERITY_IDS: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 99];

fn valid_activity_ids_for_class(class_uid: u32) -> Option<&'static [u8]> {
    match class_uid {
        1001 => Some(&[1, 2, 3, 4, 5, 99]),
        1006 => Some(&[1, 2, 3, 99]),
        2002 | 2003 | 2004 => Some(&[1, 2, 3, 99]),
        3001 => Some(&[1, 2, 3, 7, 8, 9, 12, 99]),
        3002 => Some(&[1, 2, 3, 99]),
        4001 => Some(&[1, 2, 3, 4, 5, 6, 99]),
        4002 => Some(&[1, 2, 3, 4, 5, 6, 7, 99]),
        4003 => Some(&[1, 2, 3, 99]),
        4004 => Some(&[1, 2, 3, 4, 99]),
        _    => None,
    }
}

fn expected_category(class_uid: u32) -> Option<(u32, &'static str)> {
    match class_uid {
        1001..=1099 => Some((1, "System Activity")),
        2001..=2099 => Some((2, "Findings")),
        3001..=3099 => Some((3, "Identity & Access Management")),
        4001..=4099 => Some((4, "Network Activity")),
        5001..=5099 => Some((5, "Discovery")),
        6001..=6099 => Some((6, "Application Activity")),
        _           => None,
    }
}

/// Validate an `OcsfRecord` against OCSF 1.7.0 schema constraints.
/// Returns a `Vec` of static violation strings — empty means fully compliant.
pub(crate) fn validate_ocsf_record(rec: &OcsfRecord) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = Vec::new();

    if !VALID_CLASS_UIDS.contains(&rec.class_uid) {
        v.push("class_uid not in OCSF 1.7.0 schema");
    }
    if !VALID_SEVERITY_IDS.contains(&rec.severity_id) {
        v.push("severity_id out of range (expected 0-6 or 99)");
    }
    if rec.type_uid != rec.class_uid * 100 + rec.activity_id as u32 {
        v.push("type_uid != class_uid * 100 + activity_id");
    }
    if let Some(valid_ids) = valid_activity_ids_for_class(rec.class_uid) {
        if !valid_ids.contains(&rec.activity_id) {
            v.push("activity_id not valid for this class_uid");
        }
    }
    if let Some((exp_uid, exp_name)) = expected_category(rec.class_uid) {
        if rec.category_uid != exp_uid {
            v.push("category_uid inconsistent with class_uid");
        }
        if rec.category_name != exp_name {
            v.push("category_name inconsistent with class_uid");
        }
    }
    if rec.time == 0 {
        v.push("time is 0 — @timestamp missing or unparseable in source event");
    }

    v
}

/// Run the validator and emit warnings on violations.  Called from `transform()`.
pub(crate) fn check_and_warn(rec: &OcsfRecord) {
    if !OCSF_VALIDATE.load(Ordering::Relaxed) { return; }
    let violations = validate_ocsf_record(rec);
    if !violations.is_empty() {
        OCSF_VIOLATION_COUNT.fetch_add(violations.len() as u64, Ordering::Relaxed);
        warn!(
            class_uid = rec.class_uid,
            rule_id   = %rec.finding_uid,
            violations = ?violations,
            "OCSF schema violation(s) — event still recorded"
        );
    }
}
