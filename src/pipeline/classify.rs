// ─── OCSF class classification ────────────────────────────────────────────────
//
// OCSF 1.7.0 class hierarchy (those relevant to Wazuh telemetry):
//
//  Cat 1 – System Activity
//    1001 File System Activity   – syscheck, sysmon file events
//    1006 Process Activity       – sysmon process, auditd execve
//
//  Cat 2 – Findings
//    2002 Vulnerability Finding  – vulnerability-detector
//    2003 Compliance Finding     – SCA, OpenSCAP, CIS-CAT
//    2004 Detection Finding      – catch-all (IDS rules, Wazuh custom rules)
//
//  Cat 3 – Identity & Access Management
//    3001 Account Change         – adduser, userdel, passwd, groupmod
//    3002 Authentication         – sshd, PAM, sudo, Windows logon/logoff
//
//  Cat 4 – Network Activity
//    4001 Network Activity       – firewall drops/allows
//    4002 HTTP Activity          – web access logs
//    4003 DNS Activity           – named / BIND / Sysmon DNS
//    4004 DHCP Activity          – dhcpd leases

pub(crate) struct OcsfClass {
    pub(crate) class_uid: u32,
    pub(crate) class_name: &'static str,
    pub(crate) category_uid: u32,
    pub(crate) category_name: &'static str,
}

/// Map Wazuh rule groups + decoder name → correct OCSF class.
///
/// Rules are ordered from most-specific to least-specific; the first
/// match wins.  The final fallback is Detection Finding (2004).
pub(crate) fn classify_event(groups: &[&str], decoder: &str, location: &str) -> OcsfClass {
    macro_rules! cls {
        ($uid:expr, $name:expr, $cat:expr, $catname:expr) => {
            OcsfClass {
                class_uid: $uid,
                class_name: $name,
                category_uid: $cat,
                category_name: $catname,
            }
        };
    }
    let g = |s: &str| groups.contains(&s);
    let ga = |ss: &[&str]| ss.iter().any(|&s| groups.contains(&s));

    let dec = decoder.to_ascii_lowercase();
    let loc = location.to_ascii_lowercase();

    // ── Cloud / Integration sources ──────────────────────────────────────
    if dec.contains("vpcflow")
        || dec.contains("vpc-flow")
        || g("amazon-vpcflow")
        || g("aws_vpcflow")
    {
        return cls!(4001, "Network Activity", 4, "Network Activity");
    }
    if dec.contains("guardduty")
        || dec.contains("guard-duty")
        || g("amazon-guardduty")
        || g("aws-guardduty")
    {
        return cls!(2002, "Vulnerability Finding", 2, "Findings");
    }
    // AWS Inspector and Macie generate security findings → Vulnerability Finding
    if g("aws_inspector") || g("aws_macie") {
        return cls!(2002, "Vulnerability Finding", 2, "Findings");
    }
    // AWS Config generates compliance findings
    if g("aws_config") {
        return cls!(2003, "Compliance Finding", 2, "Findings");
    }
    // AWS WAF and ALB produce HTTP-layer events
    if g("aws_waf") {
        return cls!(4002, "HTTP Activity", 4, "Network Activity");
    }
    if g("aws_alb") || g("aws_elb") {
        return cls!(4002, "HTTP Activity", 4, "Network Activity");
    }
    // AWS S3 Server Access Logs → HTTP Activity
    if g("aws_s3") || g("s3") {
        return cls!(4002, "HTTP Activity", 4, "Network Activity");
    }
    if dec.contains("okta")
        || dec.contains("azure-ad")
        || dec.contains("azure_ad")
        || dec.contains("azure-active")
        || dec.contains("onelogin")
        || g("okta")
        || g("azure-ad")
        || g("azure_ad")
        || g("onelogin")
    {
        return cls!(3002, "Authentication", 3, "Identity & Access Management");
    }
    if dec.contains("zeek") || dec.contains("bro-ids") || g("zeek") || g("bro") {
        return cls!(4001, "Network Activity", 4, "Network Activity");
    }
    if (dec.contains("cloudtrail") || dec.contains("aws-cloudtrail"))
        && ga(&["authentication", "aws_iam", "aws-iam"])
    {
        return cls!(3002, "Authentication", 3, "Identity & Access Management");
    }

    // ── Cat 1: System Activity ───────────────────────────────────────────
    if ga(&["syscheck", "syscheck_file", "sysmon_file", "fim_config"])
        || (g("sysmon") && g("sysmon_file"))
    {
        return cls!(1001, "File System Activity", 1, "System Activity");
    }
    if ga(&[
        "sysmon_process",
        "process_creation",
        "process_activity",
        "execve",
        "audit_command",
    ]) || (g("sysmon")
        && !ga(&[
            "sysmon_file",
            "sysmon_network_connection",
            "sysmon_dns_query",
            "sysmon_registry",
        ]))
    {
        return cls!(1006, "Process Activity", 1, "System Activity");
    }

    // ── Cat 2: Findings ──────────────────────────────────────────────────
    if ga(&["vulnerability-detector", "vulnerability", "vuls"]) || dec.contains("vulnerability") {
        return cls!(2002, "Vulnerability Finding", 2, "Findings");
    }
    if ga(&["oscap", "sca", "ciscat"]) {
        return cls!(2003, "Compliance Finding", 2, "Findings");
    }
    // MS Graph Security (Microsoft 365 Defender) — produces security alert findings
    if dec.contains("ms-graph") || dec.contains("ms_graph") || g("ms-graph") {
        return cls!(2002, "Vulnerability Finding", 2, "Findings");
    }

    // ── Cat 3: Identity & Access Management ─────────────────────────────
    if ga(&[
        "adduser",
        "addgroup",
        "userdel",
        "groupdel",
        "usermod",
        "account_changed",
        "user_management",
        "group_management",
    ]) {
        return cls!(3001, "Account Change", 3, "Identity & Access Management");
    }
    if ga(&[
        "authentication",
        "authentication_failed",
        "authentication_success",
        "pam",
        "sudo",
        "su",
        "sshd",
        "win_authentication",
        "windows_logon",
    ]) || dec == "pam"
        || dec == "sudo"
        || dec == "su"
        || dec == "sshd"
        || dec.ends_with("_auth")
        || dec.contains("auth")
    {
        return cls!(3002, "Authentication", 3, "Identity & Access Management");
    }

    // ── Cat 4: Network Activity ──────────────────────────────────────────
    if ga(&["dns", "sysmon_dns_query"]) || dec.contains("dns") || dec.contains("named") {
        return cls!(4003, "DNS Activity", 4, "Network Activity");
    }
    if g("dhcp") || dec.contains("dhcp") {
        return cls!(4004, "DHCP Activity", 4, "Network Activity");
    }
    // Cloudflare WAF rules produce HTTP-level events
    if dec.contains("cloudflare") || g("WAF") || g("Cloudflare") || g("cloudflare") {
        return cls!(4002, "HTTP Activity", 4, "Network Activity");
    }
    if ga(&[
        "web",
        "web-log",
        "web_accesslog",
        "web_attack",
        "apache",
        "nginx",
        "iis",
        "squid",
        "haproxy",
    ]) || dec.contains("apache")
        || dec.contains("nginx")
        || dec.contains("iis")
        || dec.contains("squid")
        || loc.ends_with("access.log")
        || loc.contains("access_log")
    {
        return cls!(4002, "HTTP Activity", 4, "Network Activity");
    }
    if ga(&[
        "firewall",
        "iptables",
        "ids",
        "suricata",
        "snort",
        "paloalto",
        "fortigate",
        "cisco",
        "pfsense",
        "checkpoint",
        "juniper",
        "netscreen",
        "sysmon_network_connection",
    ]) || dec.contains("fortigate")
        || dec.contains("paloalto")
        || dec.contains("cisco")
        || dec.contains("pfsense")
        || dec.contains("checkpoint")
        || dec.contains("iptables")
        || dec.contains("suricata")
        || dec.contains("snort")
        || dec.contains("netfilter")
    {
        return cls!(4001, "Network Activity", 4, "Network Activity");
    }

    // ── Default: Detection Finding (2004) ────────────────────────────────
    cls!(2004, "Detection Finding", 2, "Findings")
}

// ─── Severity mapping ─────────────────────────────────────────────────────────

pub(crate) fn map_severity(level: u64) -> (u8, &'static str) {
    // OCSF 1.7.0 severity_id: 0=Unknown 1=Informational 2=Low 3=Medium 4=High 5=Critical
    match level {
        0 => (0, "Unknown"),
        1..=3 => (1, "Informational"),
        4..=6 => (2, "Low"),
        7..=9 => (3, "Medium"),
        10..=12 => (4, "High"),
        _ => (5, "Critical"),
    }
}
