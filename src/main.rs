//! Wazuh → OCSF → ClickHouse ETL pipeline
//!
//! ## Routing (identical to siem_alerts_consumer.py)
//!
//! - `location` is in SPECIAL_LOCATIONS → table named after the **location**
//!   (use for agentless/integration sources: AWS, Office365, GitHub, syslog
//!    forwarded from network devices).
//! - Otherwise → table named after the **agent.name**
//!   (Linux hosts, Windows hosts, etc. each get their own table automatically).
//!
//! ## Custom field mapping  (config/field_mappings.toml)
//!
//! Add custom decoder fields and map them to OCSF columns.
//! The file is hot-reloaded every 10 s — no restart required.
//!
//! ## OCSF schema versioning
//!
//! Set `ocsf_version` in field_mappings.toml.  When you upgrade OCSF, add
//! entries to `[ocsf_field_renames]` and the binary will print the exact
//! ALTER TABLE statements needed at startup.
//!
//! ## Environment variables / .env file
//!
//!   CLICKHOUSE_URL        http://localhost:8123
//!   CLICKHOUSE_DATABASE   wazuh_ocsf
//!   CLICKHOUSE_USER       default
//!   CLICKHOUSE_PASSWORD   (empty)
//!   ALERTS_FILE           /var/ossec/logs/alerts/alerts.json
//!   FIELD_MAPPINGS_FILE   config/field_mappings.toml
//!   STATE_FILE            state/alerts.pos   (byte-offset resume on restart)
//!   SPECIAL_LOCATIONS     (empty by default — see .env.example)
//!   DATA_TTL_DAYS         (omit to keep forever)

use std::collections::{HashMap, HashSet};
use std::io::SeekFrom;
use std::os::unix::fs::MetadataExt; // .ino() – Linux inode for rotation detection
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clickhouse::{Client, Row};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader as TokioBufReader};
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, error, info, trace, warn};

// ─── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_ALERTS_FILE: &str     = "/var/ossec/logs/alerts/alerts.json";
const DEFAULT_MAPPINGS_FILE: &str   = "config/field_mappings.toml";
const DEFAULT_STATE_FILE: &str      = "state/alerts.pos";
const CONFIG_POLL_SECS: u64         = 10;
// BATCH_SIZE, FLUSH_INTERVAL_SECS and CHANNEL_CAP are now tunable via env vars.
// Defaults below match the old hardcoded values.
const DEFAULT_BATCH_SIZE: usize       = 5_000;
const DEFAULT_FLUSH_INTERVAL_SECS: u64 = 5;
/// Bounded channel capacity between reader and processor tasks.
/// At ~1 KB per alert line the default (~50 MB) is kept in-flight.
/// When ClickHouse is slow the reader blocks here (backpressure) — nothing dropped.
const DEFAULT_CHANNEL_CAP: usize      = 50_000;

// ─── Static path arrays (zero runtime cost) ───────────────────────────────────
//
// These cover every field name found across all Wazuh default decoders
// (all 280+ fields used in 2+ decoder files, sourced from
//  /var/ossec/ruleset/decoders + /var/ossec/etc/decoders).

const SRC_IP: &[&str] = &[
    // Generic syslog / OSSEC (256 decoders use srcip)
    "srcip", "src_ip", "source_ip", "source_address", "sourceip", "sourceIpAddress",
    "src", "ip", "host_ip", "ip_address", "proxy_ip", "xff_address",
    // Lowercase variants seen across miscellaneous decoders
    "locip",         // pfSense/ipfw: local (source) IP
    "ipaddr",        // DHCP / keepalived
    "ip.address",    // dot-notation nested field
    "LocalIp",       // Prelude/OSSIM sensor format
    "identSrc",      // Prelude correlation source
    "assignip",      // DHCP lease assignment
    "client_dyn_ip", // dynamic-IP allocation logs
    // Suricata / Snort
    "alert.src_ip",
    // Windows Event Channel
    "win.eventdata.ipAddress", "win.eventdata.sourceAddress", "win.eventdata.IpAddress",
    // AWS CloudTrail / GuardDuty
    "aws.sourceIPAddress", "aws.requestParameters.ipAddress",
    // GCP Audit
    "gcp.protoPayload.requestMetadata.callerIp",
    // Office365
    "office365.ActorIpAddress", "office365.ClientIP",
    // GitHub audit
    "github.actor_ip",
    // VPN / IPSec / proxy
    "remip",           // remote peer IP in IPSec/VPN tunnels
    "tunnelip",        // tunnel source endpoint IP
    "forwardedfor",    // HTTP X-Forwarded-For (original client behind proxy)
    "x_forwarded_for", // underscore variant of X-Forwarded-For
    // CEF / ArcSight fields
    "cs1",
];

const DST_IP: &[&str] = &[
    "dstip", "dst_ip", "dest_ip", "destination_ip", "destip", "dstname",
    "destinationIpAddress", "destination_address",
    "dst",
    "dstcip",  // Cisco ASA: destination translated IP
    "dhost",   // CEF/ArcSight destination host (IP)
    "alert.dest_ip",
    "win.eventdata.destinationIp", "win.eventdata.DestinationIp",
];

const SRC_PORT: &[&str] = &[
    "srcport", "src_port", "source_port",
    "locport",   // pfSense/ipfw: local (source) port
    "LocalPort", // Prelude sensor format
    "s_port",    // some syslog decoders
    "spt",       // CEF Source Port
    "sport",     // generic source port alias (haproxy, misc)
    "alert.src_port",
    "win.eventdata.ipPort", "win.eventdata.IpPort",
    "cs2",
];

const DST_PORT: &[&str] = &[
    "dstport", "dst_port", "dest_port", "destination_port",
    "remport", // pfSense/ipfw: remote (destination) port
    "dpt",     // CEF Destination Port
    "dport",   // generic destination port alias (haproxy, misc)
    "alert.dest_port",
    "win.eventdata.destinationPort", "win.eventdata.DestinationPort",
];

const NAT_SRC_IP: &[&str] = &[
    "nat_srcip", "nat_src_ip", "nat_source_ip",
    // FortiGate: source NAT translated IP
    "transip",
    // PAN-OS
    "mapped_src_ip",
    // Check Point / Juniper: translated source IP
    "xlatesrc",
    // Cisco ASA / generic
    "tran_src_ip",
];

const NAT_DST_IP: &[&str] = &[
    "nat_dstip", "nat_dst_ip", "nat_destination_ip",
    "nat_dest_ip", "mapped_dst_ip",
    "xlatedst",    // Check Point / Juniper: translated destination IP
    "tran_dst_ip", // Cisco ASA / generic
];

const NAT_SRC_PORT: &[&str] = &[
    "nat_srcport", "nat_src_port", "nat_source_port",
    // FortiGate: translated source port
    "transport",
    "mapped_src_port",
    "xlatesport",    // Check Point / Juniper: translated source port
    "tran_src_port", // Cisco ASA / generic
];

const NAT_DST_PORT: &[&str] = &[
    "nat_dstport", "nat_dst_port", "nat_destination_port",
    "nat_dest_port", "mapped_dst_port",
    "xlatedport",    // Check Point / Juniper: translated destination port
    "tran_dst_port", // Cisco ASA / generic
];

const PROTOCOL: &[&str] = &[
    "protocol", "proto", "transport", "protocol_id",
    "Protocol",         // uppercase variant (some vendor decoders)
    "ip_protocol",      // IP protocol number (auditd, netfilter)
    "alert.proto",
    "win.eventdata.protocol",
    "network_forwarded_protocol",
];

const BYTES_IN: &[&str] = &[
    // FortiGate
    "rcvdbyte",
    // generic
    "bytes_recv", "bytes_in", "bytesIn", "bytes",
    // Case variants / other vendors
    "BytesReceived",     // Check Point / Cylance
    "bytes_received",    // pfSense / generic
    "bytes_from_server", // proxy / WAF logs (server → client = inbound)
];

const BYTES_OUT: &[&str] = &[
    // FortiGate
    "sentbyte",
    // generic
    "bytes_sent", "bytes_out", "bytesOut",
    // Case variants / other vendors
    "BytesSent",         // Check Point / Cylance
    "bytes_from_client", // proxy / WAF logs (client → server = outbound)
];

const ACTOR_USER: &[&str] = &[
    // Generic (80 decoders use user/srcuser/username)
    "srcuser", "src_user", "user", "username", "user_name", "source_user",
    "userName", "userAccount",
    "userid", "userID",      // lowercase / camelCase user-id variants
    "LoggedUser",            // Check Point / Prelude: currently-logged-in user
    "SourceUserName",        // Check Point R80 field name
    "client_user",           // proxy / squid decoders
    "database_user",         // MySQL / PostgreSQL audit
    "ldap_data.Username",    // OpenLDAP decoder
    // auditd
    "audit.acct", "audit.auid",
    // Common authlog / syslog user fields
    "login",         // generic login name (sshd, PAM, ftpd)
    "logname",       // syslog logname field (su, sudo)
    "usrName",       // ArcSight / LEEF alternate casing
    "xauthuser",     // VPN XAUTH / L2TP authenticated user
    "account_name",  // Windows/LDAP account name
    "subject.account_name", // Windows Security subject account (nested)
    // Windows — subject (the initiating service/process) or target account.
    // SubjectUserName is tried first (often SYSTEM); targetUserName is the
    // account being logged into and is the most useful for auth dashboards.
    "win.eventdata.subjectUserName", "win.eventdata.SubjectUserName",
    "win.eventdata.targetUserName",  "win.eventdata.TargetUserName",
    "win.eventdata.initiatorAccountName",
    // AWS
    "aws.userIdentity.userName", "aws.userIdentity.principalId",
    "aws.userIdentity.sessionContext.sessionIssuer.userName",
    // GCP
    "gcp.protoPayload.authenticationInfo.principalEmail",
    // Office365
    "office365.UserId",
    // GitHub
    "github.actor",
    // MariaDB/MySQL
    "mariadb.username",
    // ArcSight / CEF
    "cs5",
];

const TARGET_USER: &[&str] = &[
    "dstuser", "dst_user", "target_user", "destination_user",
    "TargetUserName", // Check Point R80 / Windows camelCase variant
    "new_user",       // useradd / adduser decoders: the account being created
    "removed_user",   // userdel / account-removal decoders: account being deleted
    "win.eventdata.targetUserName", "win.eventdata.TargetUserName",
    "win.system.security.userID",
];

const DOMAIN: &[&str] = &[
    "domain",
    "account_domain",        // Windows NTLM / LDAP domain name
    "dntdom",                // CEF destination NT domain name
    "subject.account_domain", // Windows Security subject domain (nested)
    "win.eventdata.subjectDomainName", "win.eventdata.SubjectDomainName",
    "win.eventdata.targetDomainName",  "win.eventdata.TargetDomainName",
    "aws.userIdentity.accountId",
];

const URL: &[&str] = &[
    "url", "uri", "request_uri",
    "URL", // uppercase variant (some CEF / HP ArcSight decoders)
    "win.eventdata.objectName",
    "aws.requestParameters.url",
    "gcp.protoPayload.resourceName",
    "github.repo",
    "office365.ObjectId",
];

const HTTP_METHOD: &[&str] = &[
    "method", "http_method", "reqtype",
    "aws.requestParameters.httpMethod",
];

const HTTP_STATUS: &[&str] = &[
    "http_response_code", "http_status_code", "http_status",
    "response_code", "status_code",
];

const APP_NAME: &[&str] = &[
    "app", "application", "appName",
    "service", "service_name",
    "product_name",  // generic product/software name (many vendors)
    "product",       // compact product field
    "protocol",      // some decoders re-use protocol as app
];

const FILE_NAME: &[&str] = &[
    "filename", "file_id",
    "sysmon.targetfilename",
    "audit.file.name",
    "TargetPath",
    "TargetFileName",           // Check Point / Windows Sysmon (target of file op)
    "SourceFilePath",           // Check Point: source file full path
    "ChildPath",                // sysmon process-create: child executable path
    "ParentPath",               // sysmon process-create: parent executable path
    // Windows Defender / Microsoft Security
    "win.eventdata.objectName",
    "defender.path",            // Defender threat path
    "defender.pathfound",       // Defender scan hit
    // Antivirus / Cylance / EDR
    "virus", "defender.name",
    "cylance_threats.file_name", "cylance_threats.file_path",
    "cylance_events.filepath",  // Cylance event filepath
    "infected_file_path",       // generic AV alert field
    "target_file",              // target file in various decoders
    "path",                     // generic path field (syslog, Linux)
    "Path",                     // uppercase variant (CEF / Windows)
    "sysmon.imageLoaded",       // Sysmon event 7: DLL/image being loaded
];

const PROCESS_NAME: &[&str] = &[
    "sysmon.image", "sysmon.Image",
    "audit.exe", "audit.command",
    "command", "program", "process",
    "SourceProcessName",  // Check Point / Cylance: initiating process
    "ChildProcessName",   // parent-process audit records
    "defender.processname",
    "process.name",        // dot-notation process name (various)
    "sysmon.commandLine",  // Sysmon Command Line (full invocation string)
    "sysmon.targetImage",  // Sysmon Event 8/10: target process image
    "sysmon.parentImage",  // Sysmon parent process image path
    "sysmon.sourceImage",  // Sysmon source process (thread injection etc.)
    "win.eventdata.image", "win.eventdata.Image",
    "win.eventdata.ProcessName",
];

const PROCESS_ID: &[&str] = &[
    "sysmon.processId", "sysmon.ProcessId",
    "sysmon.processid",  // Sysmon lowercase variant (older Wazuh agents)
    "audit.pid",
    "pid",               // generic lowercase PID (netstat, auditd, misc)
    "PID",               // uppercase PID (Check Point, Cylance LEEF)
    "process.pid",       // dot-notation PID (docker, nested decoders)
    "win.eventdata.processId", "win.eventdata.ProcessId",
    "win.system.execution.processId",
];

const RULE_NAME: &[&str] = &[
    "rule_name", "attack.name", "attack",
    "sysmon.signature",
    "sysmon.ruleName",    // Sysmon v15+ matching rule name
    "signature",
    "ThreatName",         // Cylance / CrowdStrike threat name
    "AnalyzerRuleName",   // Prelude IDMEF analyzer rule name
];

const CATEGORY: &[&str] = &[
    "category", "cat", "appcat", "application_category",
    // PAN-OS / FortiGate
    "subtype", "sub_cat",
    // Windows / CEF
    "Category",
    // EDR / AV threat category
    "ThreatCategory",  // Cylance threat category field
    "threat_category", // generic threat category (Trend, Sophos, etc.)
];

const IFACE_IN: &[&str] = &[
    "srcintf", "inbound_interface", "interface",
    "packet_incoming_interface",
    "source_zone", "srczone",  // zone-based firewall ingress zone
    "in_interface",            // generic inbound interface
    "inzone",                  // FortiGate ingress zone
    "ifname",  "if_name",     // interface name (pfSense, Linux)
];

const IFACE_OUT: &[&str] = &[
    "dstintf", "outbound_interface",
    "destination_zone", "dstzone",   // zone-based firewall egress zone
    "out_interface",                  // generic outbound interface
    "outzone",                        // FortiGate egress zone
    "outintf",                        // compact outbound interface name
    "dstinterface",                   // FortiGate destination interface
];

const SRC_HOSTNAME: &[&str] = &[
    "hostname", "srchost", "src_host", "sourceHostname", "source_hostname",
    "dvchost",
    "host",            // generic syslog hostname
    "HostName",        // Prelude / Check Point PascalCase variant
    "AnalyzerHostName",// Prelude IDMEF analyzer host
    "TargetHostName",  // Check Point target device hostname
    "identHostName",   // ident/IDMEF source hostname
    "win.system.computer", "win.eventdata.workstationName",
    "win.eventdata.WorkstationName",
    "srcname",        // source name / hostname (LEEF, ArcSight)
    "sname",          // compact source name (some LEEF decoders)
    "caller_computer", // Windows Security logon: caller computer name
    "machine_name",   // generic machine name
    "machinename",    // no-underscore variant
];

const DST_HOSTNAME: &[&str] = &[
    "dsthost", "dst_host", "destinationHostname", "destination_hostname",
    "sysmon.destinationHostname", // Sysmon Event 3: network connection dest host
    "server_name",               // HTTP SNI / TLS server name
];

const ACTION: &[&str] = &[
    "action", "log_action",
    "Action",             // Check Point / Prelude: PascalCase variant
    "ThreatActionTaken",  // Cylance / CrowdStrike EDR response action
    "RegAction",          // registry hive audit action (create/modify/delete)
    "data.action",        // nested data.action from some syslog decoders
    "alert.action",
    "fw_action",
    "act",                // CEF
    "aws.eventName",
    "gcp.protoPayload.methodName",
    "github.action",
    "office365.Operation",
    "defender.action",    // Windows Defender quarantine / block / allow
    "operation",          // generic operation name (MariaDB, Check Point, OSSIM)
    "rule_action",        // action from the matching rule (Suricata, Snort)
    "utmaction",          // FortiGate UTM action
];

const STATUS: &[&str] = &[
    "status", "result", "outcome",
    "data.status",               // nested data.status from generic decoders
    "cylance_events.eventstatus", // Cylance event status
    "win.eventdata.status",  "win.eventdata.Status",
    "win.eventdata.failureReason",
    "aws.errorCode",
    "audit.res",
    "audit.success",   // auditd success field ("yes"/"no" or "1"/"0")
];

// ─── App config ─────────────────────────────────────────────────────────────

/// Selects which input source the pipeline reads from.
/// Exactly one is active at a time; the downstream (channel → transform →
/// ClickHouse) is identical for both.
#[derive(Debug, Clone, PartialEq)]
enum InputMode {
    /// Tail `ALERTS_FILE` from disk (default, same as Filebeat/Logstash).
    File,
    /// Subscribe to a wazuh-analysisd ZeroMQ PUB socket (zero disk I/O).
    ZeroMq,
}

struct AppConfig {
    clickhouse_url:      String,
    clickhouse_db:       String,
    clickhouse_user:     String,
    clickhouse_password: String,
    alerts_file:         String,
    mappings_file:       PathBuf,
    /// Path to the byte-offset state file; written atomically after every flush.
    state_file:          PathBuf,
    special_locations:   Vec<String>,
    data_ttl_days:       Option<u32>,
    /// When true (default) and no prior state exists, seek to the END of the
    /// alerts file on first start instead of replaying from byte 0.
    /// Set SEEK_TO_END_ON_FIRST_RUN=false to replay the whole file from the start.
    seek_to_end_on_first_run: bool,
    /// Flush a per-table batch to ClickHouse once it reaches this many rows.
    /// Tune upward for higher EPS (e.g. 10_000) to reduce HTTP round-trips.
    batch_size: usize,
    /// Also flush on this timer even if batch_size is not reached (low-EPS safety net).
    flush_interval_secs: u64,
    /// Bounded mpsc channel depth between reader and processor tasks.
    /// Each slot is ~1 KB so the default of 50_000 ≈ 50 MB max in-flight.
    channel_cap: usize,
    /// Which input source to use: File (default) or ZeroMq.
    input_mode: InputMode,
    /// ZeroMQ URI to subscribe to when input_mode = ZeroMq.
    /// Must match the <zeromq_uri> in wazuh-manager ossec.conf.
    zeromq_uri: String,
}

impl AppConfig {
    fn from_env() -> Self {
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
                .unwrap_or(true), // default: skip old data on first run
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
                _ => InputMode::File,  // default
            },
            zeromq_uri: std::env::var("ZEROMQ_URI")
                .unwrap_or_else(|_| "tcp://localhost:11111".into()),
        }
    }
}

/// Parse an env var as `usize`, warning if the value is present but not a valid integer.
fn parse_env_usize(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Err(_) => default,
        Ok(s) => s.trim().parse::<usize>().unwrap_or_else(|e| {
            warn!("{name}={s:?} is not a valid integer ({e}) — using default {default}");
            default
        }),
    }
}

/// Parse an env var as `u64`, warning if the value is present but not a valid integer.
fn parse_env_u64(name: &str, default: u64) -> u64 {
    match std::env::var(name) {
        Err(_) => default,
        Ok(s) => s.trim().parse::<u64>().unwrap_or_else(|e| {
            warn!("{name}={s:?} is not a valid integer ({e}) — using default {default}");
            default
        }),
    }
}

// ─── State persistence ────────────────────────────────────────────────────────
//
// The state file stores the inode + byte offset of the last successfully
// flushed batch.  On restart the reader seeks directly to that position,
// ensuring:
//   • After a clean stop: resume from exact position — zero duplicate rows.
//   • After a crash:      re-process at most CHANNEL_CAP + BATCH_SIZE – 1 lines
//                         (at-least-once delivery — far better than data loss).
//   • After file rotation while stopped: inode mismatch detected → start from 0
//                         on the new file (no lines skipped).

#[derive(Debug, Default, Clone)]
struct TailState {
    /// Linux inode of the tailed file when this state was saved.
    /// 0 = not yet known (first run / pre-existing state without inode).
    inode:  u64,
    /// Byte offset immediately after the last FLUSHED line.
    offset: u64,
}

struct StateStore { path: PathBuf }

impl StateStore {
    fn new(path: PathBuf) -> Self { Self { path } }

    /// Load saved state.  Returns default (offset=0, inode=0) when absent.
    fn load(&self) -> TailState {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t)  => t,
            Err(_) => return TailState::default(),
        };
        let mut s = TailState::default();
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("inode=")  { s.inode  = v.trim().parse().unwrap_or(0); }
            if let Some(v) = line.strip_prefix("offset=") { s.offset = v.trim().parse().unwrap_or(0); }
        }
        s
    }

    /// Atomically persist state: write to .tmp then rename (crash-safe).
    fn save(&self, s: &TailState) -> std::io::Result<()> {
        if let Some(p) = self.path.parent() { std::fs::create_dir_all(p)?; }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, format!("inode={}\noffset={}\n", s.inode, s.offset))?;
        std::fs::rename(&tmp, &self.path)
    }
}

// ─── File tailer ──────────────────────────────────────────────────────────────
//
// Custom async file tailer that:
//   1. Opens the file at a saved byte offset (cheap seek, no re-read).
//   2. Returns complete lines one at a time; on EOF sleeps 50 ms and retries.
//   3. Detects log rotation (inode change) and file truncation.
//   4. Never drops bytes: partial lines at EOF are re-read on the next call.

struct FileTailer {
    path:   PathBuf,
    reader: TokioBufReader<TokioFile>,
    /// Byte offset of the START of the next line to return.
    offset: u64,
    /// Linux inode at the time this tailer was opened.
    inode:  u64,
}

impl FileTailer {
    async fn open(path: &Path, offset: u64) -> Result<Self> {
        let inode = std::fs::metadata(path).map(|m| m.ino()).unwrap_or(0);
        let mut file = TokioFile::open(path).await
            .with_context(|| format!("open {}", path.display()))?;
        file.seek(SeekFrom::Start(offset)).await?;
        Ok(Self {
            path:   path.to_path_buf(),
            reader: TokioBufReader::with_capacity(256 * 1024, file),
            offset,
            inode,
        })
    }

    /// Read the next complete (newline-terminated) line.
    ///
    /// Returns:
    ///   `Ok(Some(line))` – a complete trimmed line
    ///   `Ok(None)`       – EOF; caller should sleep briefly and retry
    ///   `Err(_)`         – I/O error
    async fn next_line(&mut self) -> Result<Option<String>> {
        let mut buf = String::new();
        let n = self.reader.read_line(&mut buf).await?;
        if n == 0 {
            return Ok(None); // clean EOF
        }
        if buf.ends_with('\n') {
            self.offset += n as u64;
            Ok(Some(buf.trim_end_matches('\n').trim_end_matches('\r').to_string()))
        } else {
            // Partial line: Wazuh is still writing this line.
            // Seek back to before this partial read so we re-read it complete next time.
            self.reader.seek(SeekFrom::Start(self.offset)).await?;
            Ok(None)
        }
    }

    /// Check if the file was rotated (inode changed) or truncated (size < offset).
    /// On detection, reinitialises the tailer to offset 0 of the new/same file.
    /// Returns `true` if a rotation/truncation was handled.
    async fn check_rotation(&mut self) -> bool {
        let meta = match tokio::fs::metadata(&self.path).await {
            Ok(m)  => m,
            Err(_) => return false, // file briefly missing during rotation
        };
        let cur_inode = meta.ino();
        let file_size = meta.len();
        if cur_inode != self.inode {
            info!("Rotation detected (inode {} → {}), reopening from start",
                  self.inode, cur_inode);
        } else if file_size < self.offset {
            info!("Truncation detected (offset {} > size {}), reopening from start",
                  self.offset, file_size);
        } else {
            return false;
        }
        match FileTailer::open(&self.path, 0).await {
            Ok(fresh) => { *self = fresh; true }
            Err(e)    => { warn!("Reopen after rotation: {e:#}"); false }
        }
    }
}

// ─── Bounded-channel reader task ─────────────────────────────────────────────
//
// This task owns the file handle.  It sends `(end_offset, line)` pairs over a
// bounded channel.  When the channel is full (ClickHouse is slow), `send`
// blocks — providing natural backpressure so memory stays bounded.
//
// The task exits only when the sender side is dropped (shutdown signal).

async fn reader_task(
    path:    PathBuf,
    initial: TailState,
    tx:      mpsc::Sender<(u64, String)>,
) {
    // Open at saved offset.
    let mut tailer = loop {
        match FileTailer::open(&path, initial.offset).await {
            Ok(t)  => break t,
            Err(e) => {
                warn!("Cannot open {}: {e:#}. Retrying in 5s…", path.display());
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };
    // Rotation-while-stopped: if saved inode ≠ current inode, the file was rotated
    // while the service was down.  The saved offset belongs to the OLD file.
    // Start from offset 0 on the NEW file to avoid skipping lines.
    if initial.inode != 0 && tailer.inode != initial.inode {
        info!("Rotation while stopped (saved_inode={} current_inode={}) — \
               starting from offset 0 on new file",
              initial.inode, tailer.inode);
        tailer = match FileTailer::open(&path, 0).await {
            Ok(t)  => t,
            Err(e) => { error!("Reopen after startup rotation: {e:#}"); return; }
        };
    }
    info!("Tailing {} from offset={} (inode={})",
          path.display(), tailer.offset, tailer.inode);
    loop {
        match tailer.next_line().await {
            Ok(Some(line)) if !line.trim().is_empty() => {
                let offset = tailer.offset;
                trace!(offset, len = line.len(), "read line");
                // Blocking send — pauses here when the channel is full
                // (backpressure).  Resumes when the processor consumes a slot.
                if tx.send((offset, line)).await.is_err() {
                    debug!("reader: channel closed — shutting down");
                    return; // channel closed → shutdown
                }
            }
            Ok(Some(_)) => { trace!("reader: blank line skipped"); } // blank line, skip
            Ok(None) => {
                // EOF: check rotation, then wait for more bytes.
                if tailer.check_rotation().await {
                    debug!(inode = tailer.inode, "reader: rotation handled — reopened from offset 0");
                } else {
                    trace!("reader: EOF — waiting for new data");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => {
                error!("reader: I/O error on {}: {e:#}", path.display());
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

// ─── ZeroMQ subscriber reader task ───────────────────────────────────────────
//
// Subscribes to the wazuh-analysisd ZeroMQ PUB socket and forwards every
// alert JSON message into the same bounded channel used by the file tailer.
// No state file, no rotation handling, no disk I/O — pure memory pipeline.
//
// Wazuh publishes raw JSON alert strings (same format as alerts.json lines).
// The offset sent is always 0 — it is only used for state persistence which
// is not needed in ZeroMQ mode (analysisd tracks its own publish position).
//
// Reconnect behaviour: if the socket is closed or the manager restarts, the
// task backs off for 5 s and reconnects — no messages are lost that analysisd
// hadn't published yet (same guarantee as Filebeat with ZeroMQ output).
async fn zmq_reader_task(
    uri: String,
    tx:  mpsc::Sender<(u64, String)>,
) {
    use zeromq::{Socket, SocketRecv, SubSocket};

    info!("ZeroMQ input: connecting to {uri}");
    loop {
        let mut socket = SubSocket::new();

        // Subscribe to all messages (empty topic filter = everything).
        if let Err(e) = socket.connect(&uri).await {
            warn!("ZeroMQ connect {uri}: {e:#}. Retrying in 5s…");
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }
        // Subscribe to all topics (wazuh publishes with no topic prefix).
        if let Err(e) = socket.subscribe("").await {
            warn!("ZeroMQ subscribe: {e:#}. Retrying in 5s…");
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }
        info!("ZeroMQ input: subscribed to {uri}");

        loop {
            match socket.recv().await {
                Ok(msg) => {
                    // ZeroMQ messages are multi-frame; wazuh sends the JSON
                    // as a single frame.  Join frames with newline just in case.
                    let raw = msg.iter()
                        .filter_map(|frame| std::str::from_utf8(frame.as_ref()).ok())
                        .collect::<Vec<_>>()
                        .join("");
                    let trimmed = raw.trim().to_string();
                    if trimmed.is_empty() { continue; }
                    // Offset 0 — ZeroMQ mode has no byte-offset concept.
                    if tx.send((0, trimmed)).await.is_err() {
                        return; // channel closed → shutdown
                    }
                }
                Err(e) => {
                    warn!("ZeroMQ recv: {e:#}. Reconnecting in 5s…");
                    break; // break inner loop → reconnect
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}


//
// Calls flush_all then atomically saves the committed offset so a restart
// resumes exactly after the last successfully written batch.

async fn do_flush(
    client:       &Client,
    cfg:          &AppConfig,
    batches:      &mut BatchMap,
    known_tables: &mut HashSet<String>,
    store:        &StateStore,
    offset:       u64,
) {
    flush_all(client, &cfg.clickhouse_url, &cfg.clickhouse_user, &cfg.clickhouse_password, &cfg.clickhouse_db, cfg.data_ttl_days, batches, known_tables).await;
    let inode = std::fs::metadata(&cfg.alerts_file).map(|m| m.ino()).unwrap_or(0);
    if let Err(e) = store.save(&TailState { inode, offset }) {
        warn!("state save: {e:#}");
    }
}

// ─── Custom mappings (field_mappings.toml) ────────────────────────────────────

/// Deserialized form of `config/field_mappings.toml`.
#[derive(Debug, Deserialize, Default)]
struct MappingsToml {
    #[serde(default)]
    meta: MetaSection,
    #[serde(default)]
    field_mappings: HashMap<String, String>,
    /// old_col → new_col renames for OCSF version migrations.
    #[serde(default)]
    ocsf_field_renames: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Default)]
struct MetaSection {
    #[serde(default = "default_ocsf_version")]
    ocsf_version: String,
}

fn default_ocsf_version() -> String { "1.7.0".to_string() }

/// Runtime-ready custom mappings, shared via `Arc<RwLock<_>>`.
#[derive(Debug, Default)]
pub struct CustomMappings {
    pub ocsf_version:     String,
    /// wazuh data field name → target OCSF column name (or extension name)
    pub field_map:        HashMap<String, String>,
    /// pending ClickHouse renames for OCSF schema migration
    pub ocsf_renames:     HashMap<String, String>,
}

impl CustomMappings {
    /// Load from a TOML file; returns a default (empty) mapping on any error.
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
}

// ─── OCSF Record ──────────────────────────────────────────────────────────────

/// Unified OCSF event record.
///
/// `class_uid` is set dynamically by `classify_event()` so every alert is
/// tagged with the correct OCSF class (Authentication, Network Activity,
/// Process Activity, …) rather than always defaulting to Detection Finding.
/// All OCSF 1.7.0 classes across 6 categories are supported.
///
///
/// Typed columns enable fast ClickHouse skip-index queries and Grafana
/// correlation dashboards.  `event_data` (full Wazuh `data.*`), `extensions`
/// (custom-mapped extras), and `unmapped` (uncaptured top-level keys) ensure
/// that absolutely no data is ever silently dropped.
#[derive(Debug, Clone, Serialize, Deserialize, Row)]
struct OcsfRecord {
    // ── Time ──────────────────────────────────────────────────────────────
    /// Unix epoch seconds — stored as DateTime in ClickHouse.
    time:              u32,
    /// ISO-8601 string for human readability.
    time_dt:           String,

    // ── OCSF metadata ─────────────────────────────────────────────────────
    /// OCSF schema version from config (e.g. "1.7.0").
    ocsf_version:      String,
    class_uid:         u32,    // 2004 = Security Finding
    class_name:        String,
    category_uid:      u32,    // 2 = Findings
    category_name:     String,
    severity_id:       u8,     // 0–6 from rule.level
    severity:          String,
    activity_id:       u8,     // See OCSF class-specific activity table
    activity_name:     String,
    /// `class_uid * 100 + activity_id` — OCSF 1.7.0 required derived field.
    /// Uniquely identifies the specific event type within a class.
    type_uid:          u32,
    /// 0=Unknown  1=Success  2=Failure  99=Other  (OCSF 1.7.0 §status_id)
    status_id:         u8,
    /// 0=Unknown  1=Low  2=Medium  3=High — derived from Wazuh rule.level.
    confidence_id:     u8,
    status:            String,
    action:            String,

    // ── Device / agent ────────────────────────────────────────────────────
    device_uid:        String,  // agent.id
    device_name:       String,  // agent.name
    device_ip:         String,  // agent.ip

    // ── Network layer ─────────────────────────────────────────────────────
    src_ip:            String,
    dst_ip:            String,
    src_port:          u16,
    dst_port:          u16,
    /// Post-NAT source IP (FortiGate transip, PAN-OS nat_srcip, …).
    nat_src_ip:        String,
    /// Post-NAT destination IP.
    nat_dst_ip:        String,
    nat_src_port:      u16,
    nat_dst_port:      u16,
    network_protocol:  String,
    bytes_in:          u64,
    bytes_out:         u64,

    // ── User / actor ──────────────────────────────────────────────────────
    /// Initiating account (srcuser, subjectUserName, AWS principalId, …).
    actor_user:        String,
    /// Targeted account (dstuser, targetUserName, …).
    target_user:       String,
    /// AD / realm / AWS account domain.
    domain:            String,

    // ── HTTP / Application ────────────────────────────────────────────────
    url:               String,
    http_method:       String,
    http_status:       u16,
    app_name:          String,

    // ── Endpoint / Process ────────────────────────────────────────────────
    src_hostname:      String,
    dst_hostname:      String,
    file_name:         String,
    process_name:      String,
    process_id:        u32,

    // ── Network routing ───────────────────────────────────────────────────
    interface_in:      String,
    interface_out:     String,

    // ── Threat / category ─────────────────────────────────────────────────
    rule_name:         String,
    category:          String,

    // ── Finding (Wazuh rule) ──────────────────────────────────────────────
    finding_title:     String,  // rule.description
    finding_uid:       String,  // rule.id
    finding_types:     String,  // rule.groups (JSON array)
    /// Raw Wazuh rule level (1–15).  Stored alongside severity_id so SOC
    /// analysts can write `WHERE wazuh_rule_level >= 12` without a lookup.
    wazuh_rule_level:  u8,
    /// rule.firedtimes — how many times this rule fired in the current
    /// analysis window. Useful for detecting repeated/burst events.
    wazuh_fired_times: u32,
    /// Comma-separated PCI DSS requirement IDs present on this rule.
    pci_dss:           String,
    /// Comma-separated GDPR article IDs present on this rule.
    gdpr:              String,
    /// Comma-separated HIPAA section IDs present on this rule.
    hipaa:             String,
    /// Comma-separated NIST 800-53 control IDs present on this rule.
    nist_800_53:       String,

    // ── MITRE ATT&CK ─────────────────────────────────────────────────────
    attack_technique:  String,
    attack_id:         String,
    attack_tactic:     String,

    // ── Source metadata ───────────────────────────────────────────────────
    src_location:      String,
    decoder_name:      String,
    manager_name:      String,

    // ── Lossless capture ─────────────────────────────────────────────────
    /// Full Wazuh `data.*` sub-object as JSON — all decoder fields preserved.
    event_data:        String,
    /// Custom-mapped fields not in the core schema (JSON object).
    extensions:        String,
    /// Top-level Wazuh fields outside the standard set.
    unmapped:          String,
    /// The original raw line verbatim — complete audit trail.
    raw_event:         String,
}

// ─── JSON navigation helpers ──────────────────────────────────────────────────

/// Navigate a dotted path `"win.eventdata.ipAddress"` through a JSON tree.
/// Returns `""` if any segment is missing or the leaf is not a string.
fn jpath<'a>(root: &'a Value, path: &str) -> &'a str {
    let mut cur = root;
    for key in path.split('.') {
        match cur.as_object().and_then(|m| m.get(key)) {
            Some(v) => cur = v,
            None    => return "",
        }
    }
    cur.as_str().unwrap_or("")
}

/// Scan `paths`; return first non-empty string found.
///
/// Lookup order per path:
/// 1. **Literal key** — `root["audit.exe"]` (some Wazuh agents/decoders flatten to
///    dotted literal keys instead of nesting).
/// 2. **Nested path** — split on `.` and navigate the JSON hierarchy (the normal
///    Wazuh case, e.g., `data → win → eventdata → ipAddress`).
fn first_str(root: &Value, paths: &[&str]) -> String {
    for &p in paths {
        // 1. Try literal key first
        if let Some(obj) = root.as_object() {
            if let Some(v) = obj.get(p) {
                if let Some(s) = v.as_str() {
                    if !s.is_empty() { return s.to_string(); }
                }
                // Key exists but isn't a usable string → skip nested for this path
                // (literal and nested refer to the same semantic field)
                continue;
            }
        }
        // 2. Navigate nested path
        let s = jpath(root, p);
        if !s.is_empty() { return s.to_string(); }
    }
    String::new()
}

/// Scan `paths` for a port value; handles both `"8080"` (string) and
/// `8080` (number).  Skips 0 (invalid port) and continues trying.
/// Tries literal key lookup first, then nested path navigation.
fn first_port(root: &Value, paths: &[&str]) -> u16 {
    for &p in paths {
        // 1. Try literal key first
        if let Some(obj) = root.as_object() {
            if let Some(val) = obj.get(p) {
                let v = match val {
                    Value::Number(n) => n.as_u64().map(|v| v.min(65535) as u16),
                    Value::String(s) => s.trim().parse::<u16>().ok(),
                    _                => None,
                };
                if let Some(port) = v { if port > 0 { return port; } }
                continue; // key found; literal and nested are the same field
            }
        }
        // 2. Navigate nested path
        let mut cur = root;
        let mut ok = true;
        for key in p.split('.') {
            match cur.as_object().and_then(|m| m.get(key)) {
                Some(v) => cur = v,
                None    => { ok = false; break; }
            }
        }
        if !ok { continue; }
        let v = match cur {
            Value::Number(n) => n.as_u64().map(|v| v.min(65535) as u16),
            Value::String(s) => s.trim().parse::<u16>().ok(),
            _                => None,
        };
        if let Some(p) = v { if p > 0 { return p; } }
    }
    0
}

/// Scan `paths` for a u64 byte counter; handles both string and number.
/// Tries literal key lookup first, then nested path navigation.
fn first_u64(root: &Value, paths: &[&str]) -> u64 {
    for &p in paths {
        // 1. Try literal key first
        if let Some(obj) = root.as_object() {
            if let Some(val) = obj.get(p) {
                let v = match val {
                    Value::Number(n) => n.as_u64(),
                    Value::String(s) => s.trim().parse::<u64>().ok(),
                    _                => None,
                };
                if let Some(n) = v { return n; }
                continue; // key found; literal and nested are the same field
            }
        }
        // 2. Navigate nested path
        let mut cur = root;
        let mut ok = true;
        for key in p.split('.') {
            match cur.as_object().and_then(|m| m.get(key)) {
                Some(v) => cur = v,
                None    => { ok = false; break; }
            }
        }
        if !ok { continue; }
        let v = match cur {
            Value::Number(n) => n.as_u64(),
            Value::String(s) => s.trim().parse::<u64>().ok(),
            _                => None,
        };
        if let Some(n) = v { return n; }
    }
    0
}

/// Retrieve a field value from the `data` object, trying the **literal key
/// first** (handles decoders like auditd that use dotted literal key names
/// such as `"audit.command"`), then falling back to nested path navigation.
fn get_data_field<'a>(data: &'a Value, field: &str) -> &'a str {
    // 1. Try literal key (e.g. data["audit.command"] when the JSON key
    //    literally contains a dot because Wazuh flattened it)
    if let Some(obj) = data.as_object() {
        if let Some(v) = obj.get(field) {
            if let Some(s) = v.as_str() {
                if !s.is_empty() { return s; }
            }
        }
    }
    // 2. Navigate nested path (the normal case)
    jpath(data, field)
}

// ─── Sanitise / route ─────────────────────────────────────────────────────────

static SANITIZE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[^a-zA-Z0-9_]+").unwrap());

/// Convert an arbitrary string to a valid lowercase SQL identifier segment.
fn sanitize_name(raw: &str) -> String {
    SANITIZE_RE
        .replace_all(raw, "_")
        .to_lowercase()
        .trim_matches('_')
        .to_string()
}

/// Determine the ClickHouse table for a Wazuh alert.
///
/// Mirrors `get_table_name()` in `siem_alerts_consumer.py`:
/// - `location` in `special_locs` → `ocsf_<location>`
/// - Otherwise                    → `ocsf_<agent_name>`
fn routing_table(
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

// ─── Severity ─────────────────────────────────────────────────────────────────

fn map_severity(level: u64) -> (u8, &'static str) {
    // OCSF 1.7.0 severity_id enum: 0=Unknown 1=Informational 2=Low 3=Medium
    //   4=High 5=Critical 99=Other.  There is NO value 6 in the spec.
    // Wazuh levels run 0-15; level 15 is the highest severity → Critical (5).
    match level {
        0       => (0, "Unknown"),
        1..=3   => (1, "Informational"),
        4..=6   => (2, "Low"),
        7..=9   => (3, "Medium"),
        10..=12 => (4, "High"),
        _       => (5, "Critical"),  // 13-14-15 and any future extension
    }
}

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
//    4001 Network Activity       – firewall drops/allows (FortiGate, PAN, ASA…)
//    4002 HTTP Activity          – web access logs (nginx, apache, IIS, squid)
//    4003 DNS Activity           – named / BIND / Sysmon DNS (Event ID 22)
//    4004 DHCP Activity          – dhcpd leases
//
// The function is pure (no allocation, just comparisons) so it adds
// virtually zero overhead to the hot transform() path.

struct OcsfClass {
    class_uid:     u32,
    class_name:    &'static str,
    category_uid:  u32,
    category_name: &'static str,
}

/// Map Wazuh rule groups + decoder name → correct OCSF class.
///
/// Rules are ordered from most-specific to least-specific; the first
/// match wins.  The final fallback is Detection Finding (2004).
fn classify_event(groups: &[&str], decoder: &str, location: &str) -> OcsfClass {
    macro_rules! cls {
        ($uid:expr, $name:expr, $cat:expr, $catname:expr) => {
            OcsfClass { class_uid: $uid, class_name: $name,
                        category_uid: $cat, category_name: $catname }
        };
    }
    // zero-copy helpers — no allocation
    let g  = |s: &str| groups.contains(&s);
    let ga = |ss: &[&str]| ss.iter().any(|&s| groups.contains(&s));

    // Pre-lower once; decoder names are always ASCII.
    let dec = decoder.to_ascii_lowercase();
    let loc = location.to_ascii_lowercase();

    // ── Cat 1: System Activity ──────────────────────────────────────────

    // 1001 File System Activity
    // Wazuh FIM (syscheck) and Sysmon File Create/Delete (Event IDs 11/23)
    if ga(&["syscheck", "syscheck_file", "sysmon_file", "fim_config"])
        || (g("sysmon") && g("sysmon_file"))
    {
        return cls!(1001, "File System Activity", 1, "System Activity");
    }

    // 1006 Process Activity
    // Sysmon process events (IDs 1/5/8), auditd execve/syscall
    if ga(&["sysmon_process", "process_creation", "process_activity",
            "execve", "audit_command"])
        || (g("sysmon") && !ga(&["sysmon_file", "sysmon_network_connection",
                                 "sysmon_dns_query", "sysmon_registry"]))
    {
        return cls!(1006, "Process Activity", 1, "System Activity");
    }

    // ── Cat 2: Findings ──────────────────────────────────────────────────

    // 2002 Vulnerability Finding
    if ga(&["vulnerability-detector", "vulnerability", "vuls"])
        || dec.contains("vulnerability")
    {
        return cls!(2002, "Vulnerability Finding", 2, "Findings");
    }

    // 2003 Compliance Finding (SCA, OpenSCAP, CIS-CAT — not mixed with net/auth)
    if ga(&["oscap", "sca", "ciscat"]) {
        return cls!(2003, "Compliance Finding", 2, "Findings");
    }

    // ── Cat 3: Identity & Access Management ─────────────────────────────

    // 3001 Account Change
    if ga(&["adduser", "addgroup", "userdel", "groupdel", "usermod",
            "account_changed", "user_management", "group_management"])
    {
        return cls!(3001, "Account Change", 3, "Identity & Access Management");
    }

    // 3002 Authentication
    // Covers: SSH, PAM, sudo/su, Windows logon (4624/4625), Kerberos, web auth
    if ga(&["authentication", "authentication_failed", "authentication_success",
            "pam", "sudo", "su", "sshd",
            "win_authentication", "windows_logon"])
        || dec == "pam" || dec == "sudo" || dec == "su" || dec == "sshd"
        || dec.ends_with("_auth") || dec.contains("auth")
    {
        return cls!(3002, "Authentication", 3, "Identity & Access Management");
    }

    // ── Cat 4: Network Activity ──────────────────────────────────────────

    // 4003 DNS Activity (before generic network — more specific)
    // Covers: named/BIND, Sysmon DNS query events (ID 22)
    if ga(&["dns", "sysmon_dns_query"])
        || dec.contains("dns") || dec.contains("named")
    {
        return cls!(4003, "DNS Activity", 4, "Network Activity");
    }

    // 4004 DHCP Activity
    if g("dhcp") || dec.contains("dhcp") {
        return cls!(4004, "DHCP Activity", 4, "Network Activity");
    }

    // 4002 HTTP Activity
    // Web access logs (nginx, Apache, IIS, HAProxy, Squid, mod_sec)
    if ga(&["web", "web-log", "web_accesslog", "web_attack",
            "apache", "nginx", "iis", "squid", "haproxy"])
        || dec.contains("apache")  || dec.contains("nginx")
        || dec.contains("iis")     || dec.contains("squid")
        || loc.ends_with("access.log") || loc.contains("access_log")
    {
        return cls!(4002, "HTTP Activity", 4, "Network Activity");
    }

    // 4001 Network Activity
    // Firewall allow/drop (FortiGate, PAN-OS, Cisco ASA, pfSense, iptables)
    // and IDS/IPS alerts (Suricata, Snort, Zeek)
    if ga(&["firewall", "iptables", "ids", "suricata", "snort",
            "paloalto", "fortigate", "cisco", "pfsense", "checkpoint",
            "juniper", "netscreen", "sysmon_network_connection"])
        || dec.contains("fortigate")  || dec.contains("paloalto")
        || dec.contains("cisco")      || dec.contains("pfsense")
        || dec.contains("checkpoint") || dec.contains("iptables")
        || dec.contains("suricata")   || dec.contains("snort")
        || dec.contains("netfilter")
    {
        return cls!(4001, "Network Activity", 4, "Network Activity");
    }

    // ── Default: Detection Finding (2004) ────────────────────────────────
    // Generic Wazuh rule match — IDS-style finding with MITRE tagging.
    cls!(2004, "Detection Finding", 2, "Findings")
}

// ─── Transform ────────────────────────────────────────────────────────────────

/// Parse one raw Wazuh alert line → `(table_name, OcsfRecord)`.
/// Returns `None` only when the line is not valid JSON.
fn transform(
    raw:          &str,
    db:           &str,
    special_locs: &[String],
    custom:       &CustomMappings,
) -> Option<(String, OcsfRecord)> {
    // Blank lines are already filtered in reader_task; this guard is a safety net.
    if raw.trim().is_empty() { return None; }
    let v: Value = serde_json::from_str(raw)
        // debug! not warn! — Wazuh writes non-JSON header lines to alerts.json during rotation;
        // these are completely normal and should not spam warn-level in production.
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
    // syscheck sub-object (FIM events) — used for activity_id classification.
    // The full object also ends up in `unmapped` for complete data preservation.
    let syscheck = section("syscheck");
    let syscheck_event = get(syscheck, "event"); // "added" | "modified" | "deleted"

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
    // Compliance tags — join array values with comma for easy SQL LIKE queries.
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
    let (sev_id, sev_label) = map_severity(rule_level);

    // ── data sub-object → all built-in field extractions ──────────────────
    let data_val = obj.get("data")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));

    let mut src_ip           = first_str(&data_val, SRC_IP);
    let mut dst_ip           = first_str(&data_val, DST_IP);
    let mut src_port         = first_port(&data_val, SRC_PORT);
    let mut dst_port         = first_port(&data_val, DST_PORT);
    let nat_src_ip           = first_str(&data_val, NAT_SRC_IP);
    let nat_dst_ip           = first_str(&data_val, NAT_DST_IP);
    let nat_src_port         = first_port(&data_val, NAT_SRC_PORT);
    let nat_dst_port         = first_port(&data_val, NAT_DST_PORT);
    let network_protocol     = first_str(&data_val, PROTOCOL);
    let bytes_in             = first_u64(&data_val, BYTES_IN);
    let bytes_out            = first_u64(&data_val, BYTES_OUT);
    let mut actor_user       = first_str(&data_val, ACTOR_USER);
    let mut target_user      = first_str(&data_val, TARGET_USER);
    let mut domain           = first_str(&data_val, DOMAIN);
    let mut url              = first_str(&data_val, URL);
    let mut http_method      = first_str(&data_val, HTTP_METHOD);
    let mut http_status      = first_port(&data_val, HTTP_STATUS); // reuse port fn (u16)
    let mut app_name         = first_str(&data_val, APP_NAME);
    let mut src_hostname     = first_str(&data_val, SRC_HOSTNAME);
    let dst_hostname         = first_str(&data_val, DST_HOSTNAME);
    let mut file_name        = first_str(&data_val, FILE_NAME);
    let mut process_name     = first_str(&data_val, PROCESS_NAME);
    let mut process_id       = first_port(&data_val, PROCESS_ID) as u32; // reuse port fn
    let interface_in         = first_str(&data_val, IFACE_IN);
    let interface_out        = first_str(&data_val, IFACE_OUT);
    let mut rule_name        = first_str(&data_val, RULE_NAME);
    let mut category         = first_str(&data_val, CATEGORY);
    let mut action           = first_str(&data_val, ACTION);
    let mut status           = first_str(&data_val, STATUS);

    // ── Custom mapping overlay ────────────────────────────────────────────
    // For each user-defined mapping, try to fill an empty built-in field
    // OR push the value into the `extensions` JSON blob.
    let mut extensions: Map<String, Value> = Map::new();
    if !custom.field_map.is_empty() {
        for (wazuh_field, ocsf_target) in &custom.field_map {
            let val = get_data_field(&data_val, wazuh_field.as_str());
            if val.is_empty() { continue; }
            let val = val.to_string();
            match ocsf_target.as_str() {
                "src_ip"          => { if src_ip.is_empty()       { src_ip       = val; } }
                "dst_ip"          => { if dst_ip.is_empty()        { dst_ip       = val; } }
                "src_port"        => { if src_port == 0 { src_port = val.parse().unwrap_or(0); } }
                "dst_port"        => { if dst_port == 0 { dst_port = val.parse().unwrap_or(0); } }
                "actor_user"      => { if actor_user.is_empty()    { actor_user   = val; } }
                "target_user"     => { if target_user.is_empty()   { target_user  = val; } }
                "domain"          => { if domain.is_empty()        { domain       = val; } }
                "url"             => { if url.is_empty()           { url          = val; } }
                "http_method"     => { if http_method.is_empty()   { http_method  = val; } }
                "http_status"     => { if http_status == 0 { http_status = val.parse().unwrap_or(0); } }
                "app_name"        => { if app_name.is_empty()      { app_name     = val; } }
                "src_hostname"    => { if src_hostname.is_empty()  { src_hostname = val; } }
                "file_name"       => { if file_name.is_empty()     { file_name    = val; } }
                "process_name"    => { if process_name.is_empty()  { process_name = val; } }
                "process_id"      => { if process_id == 0 { process_id = val.parse().unwrap_or(0); } }
                "rule_name"       => { if rule_name.is_empty()     { rule_name    = val; } }
                "category"        => { if category.is_empty()      { category     = val; } }
                "action"          => { if action.is_empty()        { action       = val; } }
                "status"          => { if status.is_empty()        { status       = val; } }
                // Unknown target → goes into extensions JSON blob
                other             => { extensions.insert(other.to_string(), Value::String(val)); }
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
    ];
    let unmapped_obj: Map<String, Value> = obj.iter()
        .filter(|(k, _)| !KNOWN.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let unmapped = serde_json::to_string(&unmapped_obj)
        .unwrap_or_else(|_| "{}".into());

    // ── Route ─────────────────────────────────────────────────────────────
    let table = routing_table(db, &agent_name, location, special_locs);

    // Classify AFTER all field extraction so decoder_name is resolved.
    let ocsf_cls = classify_event(&rule_groups, &decoder_name, location);

    // ── Activity (class-aware per OCSF 1.7.0) ────────────────────────────────
    //
    // Every OCSF class defines its own activity_id enum.  Using the wrong id
    // (e.g. "Create" on Network Activity which has no Create) produces
    // unmappable type_uid values and is a schema violation.
    let grp = |s: &str| rule_groups.contains(&s);
    let (activity_id, activity_name): (u8, &str) = match ocsf_cls.class_uid {

        // ─ 1001 File System Activity ──────────────────────────────────────
        // Activities: 1=Create  2=Read  3=Update  4=Delete  5=Rename  99=Other
        // Wazuh FIM sets syscheck.event = "added" | "modified" | "deleted".
        1001 => match syscheck_event.to_ascii_lowercase().as_str() {
            "modified" | "changed" => (3, "Update"),
            "deleted"  | "removed" => (4, "Delete"),
            _                      => (1, "Create"),  // "added" or unknown
        },

        // ─ 1006 Process Activity ──────────────────────────────────────────
        // Activities: 1=Launch  2=Terminate  3=Open  99=Other
        1006 => {
            if grp("process_stopped") || grp("process_terminated")
                || grp("sysmon_process_terminate")
            { (2, "Terminate") } else { (1, "Launch") }
        },

        // ─ 3001 Account Change ────────────────────────────────────────────
        // Activities: 1=Create User  2=Delete User  3=Update User
        //             7=Create Group 8=Delete Group 9=Update Group
        //             12=Change Password  99=Other
        3001 => {
            if      grp("userdel")                                    { (2, "Delete User")   }
            else if grp("groupdel")                                   { (8, "Delete Group")  }
            else if grp("addgroup")                                   { (7, "Create Group")  }
            else if grp("groupmod")                                   { (9, "Update Group")  }
            else if grp("usermod") || grp("account_changed")         { (3, "Update User")   }
            else if grp("passwd")  || grp("password_changed")        { (12, "Change Password") }
            else                                                      { (1, "Create User")   }
        },

        // ─ 3002 Authentication ────────────────────────────────────────────
        // Activities: 1=Logon  2=Logoff  3=Authentication Ticket  99=Other
        3002 => {
            if grp("logoff") || grp("logout") { (2, "Logoff") }
            else { (1, "Logon") }
        },

        // ─ 4001 Network Activity ─────────────────────────────────────────
        // Activities: 1=Open  2=Close  3=Reset  4=Fail  5=Refuse  6=Traffic
        // Derive from the already-extracted `action` field (firewall verdict).
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

        // ─ 4002 HTTP Activity ─────────────────────────────────────────────
        // Activities: 1=Get 2=Put 3=Post 4=Delete 5=Connect 6=Options 7=Head
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

        // ─ 4003 DNS Activity ──────────────────────────────────────────────
        // Activities: 1=Query  2=Response  3=Traffic  99=Other
        // Wazuh DNS events are always query-based (no server-side DNS logs).
        4003 => (1, "Query"),

        // ─ 4004 DHCP Activity ─────────────────────────────────────────────
        // Activities: 1=Assign  2=Renew  3=Release  4=Expire  99=Other
        4004 => (1, "Assign"),

        // ─ All other classes (2002/2003/2004/…) ──────────────────────────
        // Findings classes use: 1=Create  2=Update  3=Close
        // New/incoming findings are always "Create".
        _ => (1, "Create"),
    };

    // type_uid = class_uid * 100 + activity_id  (OCSF 1.7.0 §type_uid, required)
    let type_uid: u32 = ocsf_cls.class_uid * 100 + activity_id as u32;

    // status_id: numeric status (OCSF 1.7.0 §status_id)
    let status_id: u8 = match status.to_ascii_lowercase().as_str() {
        "success" | "allow" | "allowed" | "pass" | "passed" => 1,
        "failure" | "fail" | "failed" | "deny" | "denied"
            | "block" | "blocked" | "drop" | "dropped"
            | "reject" | "rejected" => 2,
        "" => 0,
        _ => 99,
    };

    // confidence_id: derived from Wazuh rule.level (OCSF 1.7.0 §confidence_id)
    // 0=Unknown (no level), 1=Low, 2=Medium, 3=High
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

    Some((table, OcsfRecord {
        time: time_secs,
        time_dt,
        ocsf_version:     custom.ocsf_version.clone(),
        class_uid:        ocsf_cls.class_uid,
        class_name:       ocsf_cls.class_name.into(),
        category_uid:     ocsf_cls.category_uid,
        category_name:    ocsf_cls.category_name.into(),
        severity_id:      sev_id,
        severity:         sev_label.into(),
        activity_id,
        activity_name:    activity_name.into(),
        type_uid,
        status_id,
        confidence_id,
        status,
        action,
        device_uid:       agent_id,
        device_name:      agent_name,
        device_ip:        agent_ip,
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
        category,
        finding_title:    rule_desc,
        finding_uid:      rule_id,
        finding_types,
        wazuh_rule_level:  rule_level as u8,
        wazuh_fired_times: rule_fired_times,
        pci_dss,
        gdpr,
        hipaa,
        nist_800_53,
        attack_technique: json_arr("technique"),
        attack_id:        json_arr("id"),
        attack_tactic:    json_arr("tactic"),
        src_location:     location.into(),
        decoder_name,
        manager_name,
        event_data,
        extensions:       extensions_json,
        unmapped,
        raw_event:        raw.to_string(),
    }))
}

// ─── ClickHouse DDL ───────────────────────────────────────────────────────────

/// Create database + table (idempotent).
///
/// Schema design rationale:
///
/// | Choice                                        | Benefit                                             |
/// |-----------------------------------------------|-----------------------------------------------------|
/// | `LowCardinality(String)` on enum-like cols    | 3-10× compression + 2-5× faster GROUP BY / WHERE   |
/// | `Delta(4)+ZSTD(1)` on `time`                 | ~10× compression vs plain ZSTD on timestamps       |
/// | `Delta(2)+ZSTD(1)` on port/pid cols          | Delta encodes sequential ints before compression   |
/// | `Delta(8)+ZSTD(1)` on bytes_in/out           | UInt64 run-length collapses well after transpose   |
/// | `ZSTD(3)` on high-entropy strings            | Security strings (IPs, URLs) compress well at L3   |
/// | `ORDER BY (class_uid, device_name, time)`    | Lowest cardinality first → best primary key pruning|
/// | `PARTITION BY toYYYYMM(time)`                | Monthly = ~12 partitions/year; avoids explosion    |
/// | Bloom filters on IP/user/filename cols       | `WHERE src_ip = '…'` skips ~99% of granules        |
/// | `set(0)` on finding_uid / rule_name          | Fast exact-match IDS rule lookups                  |
/// | `minmax` on numeric IDs                      | Range queries on severity / class / type skip fast |
/// | TTL clause                                   | Automatic data expiry if configured                |
async fn ensure_table(
    client:   &Client,
    url:      &str,
    user:     &str,
    password: &str,
    db:       &str,
    table:    &str,
    ttl_days: Option<u32>,
) -> Result<()> {
    // Build a client WITHOUT .with_database() for the CREATE DATABASE DDL.
    // The main `client` sends `?database=<db>` on every request; ClickHouse
    // resolves that context *before* executing the query, so CREATE DATABASE
    // fails with Code 81 (UNKNOWN_DATABASE) if the DB doesn't exist yet.
    let ddl_client = Client::default()
        .with_url(url)
        .with_user(user)
        .with_password(password);
    ddl_client
        .query(&format!("CREATE DATABASE IF NOT EXISTS `{db}`"))
        .execute().await
        .with_context(|| format!("CREATE DATABASE {db}"))?;

    let ttl = ttl_days
        .map(|d| format!("\nTTL time + INTERVAL {d} DAY"))
        .unwrap_or_default();

    // `table` may be fully-qualified "db.tbl"; backtick-quoting the whole
    // string (`db.tbl`) makes ClickHouse treat the dot as part of the name.
    // Split and quote each part separately so the DDL reads `db`.`tbl`.
    let (db_part, tbl_part) = table.split_once('.').unwrap_or((db, table));

    let ddl = format!(r#"CREATE TABLE IF NOT EXISTS `{db_part}`.`{tbl_part}` (
    -- ── Time ─────────────────────────────────────────────────────────────
    -- Delta(4) stores differences between consecutive timestamps → near-zero
    -- entropy on monotonically increasing sequences → ZSTD compresses to ~1-2 B/row.
    `time`              DateTime                        CODEC(Delta(4), ZSTD(1)),
    `time_dt`           String                          CODEC(ZSTD(3)),

    -- ── OCSF metadata ─────────────────────────────────────────────────────
    -- LowCardinality: stores a dictionary + integer references instead of
    -- full strings. For columns with <10k distinct values this gives 3-10×
    -- compression and faster GROUP BY / WHERE without any explicit indexing.
    `ocsf_version`      LowCardinality(String)          CODEC(ZSTD(1)),
    `class_uid`         UInt32                          CODEC(ZSTD(1)),
    `class_name`        LowCardinality(String)          CODEC(ZSTD(1)),
    `category_uid`      UInt32                          CODEC(ZSTD(1)),
    `category_name`     LowCardinality(String)          CODEC(ZSTD(1)),
    `severity_id`       UInt8                           CODEC(ZSTD(1)),
    `severity`          LowCardinality(String)          CODEC(ZSTD(1)),
    `activity_id`       UInt8                           CODEC(ZSTD(1)),
    `activity_name`     LowCardinality(String)          CODEC(ZSTD(1)),
    `type_uid`          UInt32                          CODEC(ZSTD(1)),
    `status_id`         UInt8                           CODEC(ZSTD(1)),
    `confidence_id`     UInt8                           CODEC(ZSTD(1)),
    `status`            LowCardinality(String)          CODEC(ZSTD(1)),
    `action`            LowCardinality(String)          CODEC(ZSTD(1)),

    -- ── Device / agent ────────────────────────────────────────────────────
    `device_uid`        String                          CODEC(ZSTD(3)),
    `device_name`       LowCardinality(String)          CODEC(ZSTD(1)),
    `device_ip`         String                          CODEC(ZSTD(3)),

    -- ── Network layer ─────────────────────────────────────────────────────
    -- High-entropy strings (IPs, hostnames) → ZSTD(3).
    -- Ports are small sequential integers → Delta(2) before ZSTD halves size.
    `src_ip`            String                          CODEC(ZSTD(3)),
    `dst_ip`            String                          CODEC(ZSTD(3)),
    `src_port`          UInt16                          CODEC(Delta(2), ZSTD(1)),
    `dst_port`          UInt16                          CODEC(Delta(2), ZSTD(1)),
    `nat_src_ip`        String                          CODEC(ZSTD(3)),
    `nat_dst_ip`        String                          CODEC(ZSTD(3)),
    `nat_src_port`      UInt16                          CODEC(Delta(2), ZSTD(1)),
    `nat_dst_port`      UInt16                          CODEC(Delta(2), ZSTD(1)),
    `network_protocol`  LowCardinality(String)          CODEC(ZSTD(1)),
    -- Byte counters can span many orders of magnitude; Delta on UInt64 helps
    -- when traffic is bursty (many similar values in a window).
    `bytes_in`          UInt64                          CODEC(Delta(8), ZSTD(1)),
    `bytes_out`         UInt64                          CODEC(Delta(8), ZSTD(1)),

    -- ── User / actor ──────────────────────────────────────────────────────
    `actor_user`        String                          CODEC(ZSTD(3)),
    `target_user`       String                          CODEC(ZSTD(3)),
    `domain`            String                          CODEC(ZSTD(3)),

    -- ── HTTP / Application ────────────────────────────────────────────────
    `url`               String                          CODEC(ZSTD(3)),
    `http_method`       LowCardinality(String)          CODEC(ZSTD(1)),
    `http_status`       UInt16                          CODEC(Delta(2), ZSTD(1)),
    `app_name`          LowCardinality(String)          CODEC(ZSTD(1)),

    -- ── Endpoint / Process ────────────────────────────────────────────────
    `src_hostname`      String                          CODEC(ZSTD(3)),
    `dst_hostname`      String                          CODEC(ZSTD(3)),
    `file_name`         String                          CODEC(ZSTD(3)),
    `process_name`      String                          CODEC(ZSTD(3)),
    -- PIDs are low integers; Delta(4) + ZSTD cuts them to near-zero.
    `process_id`        UInt32                          CODEC(Delta(4), ZSTD(1)),

    -- ── Network routing ───────────────────────────────────────────────────
    `interface_in`      LowCardinality(String)          CODEC(ZSTD(1)),
    `interface_out`     LowCardinality(String)          CODEC(ZSTD(1)),

    -- ── Threat / category ─────────────────────────────────────────────────
    `rule_name`         String                          CODEC(ZSTD(3)),
    `category`          LowCardinality(String)          CODEC(ZSTD(1)),

    -- ── Finding (Wazuh rule) ──────────────────────────────────────────────
    `finding_title`     String                          CODEC(ZSTD(3)),
    `finding_uid`       LowCardinality(String)          CODEC(ZSTD(1)),
    `finding_types`     String                          CODEC(ZSTD(3)),
    -- Raw Wazuh rule level (1–15) alongside OCSF severity_id for direct filtering.
    `wazuh_rule_level`  UInt8                           CODEC(ZSTD(1)),
    -- How many times this rule fired in the current analysis window.
    `wazuh_fired_times` UInt32                          CODEC(ZSTD(1)),
    -- Compliance framework tags (comma-separated) — enables fast LIKE queries.
    `pci_dss`           String                          CODEC(ZSTD(3)),
    `gdpr`              String                          CODEC(ZSTD(3)),
    `hipaa`             String                          CODEC(ZSTD(3)),
    `nist_800_53`       String                          CODEC(ZSTD(3)),

    -- ── MITRE ATT&CK ─────────────────────────────────────────────────────
    `attack_technique`  String                          CODEC(ZSTD(3)),
    `attack_id`         String                          CODEC(ZSTD(3)),
    `attack_tactic`     String                          CODEC(ZSTD(3)),

    -- ── Source metadata ───────────────────────────────────────────────────
    `src_location`      String                          CODEC(ZSTD(3)),
    `decoder_name`      LowCardinality(String)          CODEC(ZSTD(1)),
    `manager_name`      LowCardinality(String)          CODEC(ZSTD(1)),

    -- ── Lossless capture ─────────────────────────────────────────────────
    -- JSON blobs compress extremely well with ZSTD(3) — typical 8-20× ratio.
    `event_data`        String                          CODEC(ZSTD(3)),
    `extensions`        String                          CODEC(ZSTD(3)),
    `unmapped`          String                          CODEC(ZSTD(3)),
    `raw_event`         String                          CODEC(ZSTD(3)),

    -- ── Skip indexes ──────────────────────────────────────────────────────
    -- bloom_filter: probabilistic membership test — skips granules that
    --   definitely don't contain the searched value. FPR=0.01 means 1% false
    --   positives (still reads that granule) but skips 99% on a miss.
    --   Best for high-cardinality point lookups: IP, user, hostname, filename.
    INDEX idx_src_ip        `src_ip`        TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_dst_ip        `dst_ip`        TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_nat_src_ip    `nat_src_ip`    TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_actor_user    `actor_user`    TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_target_user   `target_user`   TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_domain        `domain`        TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_src_hostname  `src_hostname`  TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_dst_hostname  `dst_hostname`  TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_file_name     `file_name`     TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_process_name  `process_name`  TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_url           `url`           TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_attack_id     `attack_id`     TYPE bloom_filter(0.01) GRANULARITY 4,
    -- set(0): stores the full set of distinct values per granule — exact match,
    --   zero false positives. Best for low-cardinality exact-match lookups.
    INDEX idx_finding_uid   `finding_uid`   TYPE set(0)             GRANULARITY 4,
    INDEX idx_finding_title `finding_title` TYPE set(0)             GRANULARITY 4,
    INDEX idx_rule_name     `rule_name`     TYPE set(0)             GRANULARITY 4,
    -- minmax: stores min/max per granule — ideal for range scans on numerics.
    INDEX idx_severity_id      `severity_id`      TYPE minmax             GRANULARITY 4,
    INDEX idx_wazuh_rule_level `wazuh_rule_level` TYPE minmax             GRANULARITY 4,
    INDEX idx_class_uid        `class_uid`        TYPE minmax             GRANULARITY 4,
    INDEX idx_type_uid         `type_uid`         TYPE minmax             GRANULARITY 4,
    INDEX idx_http_status      `http_status`      TYPE minmax             GRANULARITY 4
)
ENGINE = MergeTree()
-- Monthly partitioning: ~12 partitions/year per table.
-- Time-range queries prune at partition level (entire months skipped instantly).
-- Daily (toYYYYMMDD) is only better when you have >100 GB/day AND TTL drops whole days.
PARTITION BY toYYYYMM(time)
-- ORDER BY: left-to-right prefix pruning.
--   class_uid  — lowest cardinality (~11 values) → biggest pruning factor.
--   device_name — groups same-agent data together → locality benefit.
--   time        — monotone → the primary key covers the most common SIEM query:
--                 WHERE class_uid = X AND device_name = Y AND time BETWEEN a AND b
ORDER BY (class_uid, device_name, time){ttl}
SETTINGS
    -- 4096 gives finer granularity than 8192 default → more granules to skip
    -- with the indexes above. Slight trade-off: slightly larger primary key.
    index_granularity       = 4096,
    min_compress_block_size = 65536,
    max_compress_block_size = 1048576"#);

    ddl_client.query(&ddl).execute().await
        .with_context(|| format!("CREATE TABLE {table}"))?;
    Ok(())
}

// ─── Batch / flush ────────────────────────────────────────────────────────────

type BatchMap = HashMap<String, Vec<OcsfRecord>>;

async fn insert_batch(
    client:  &Client,
    table:   &str,
    records: Vec<OcsfRecord>,
) -> Result<()> {
    if records.is_empty() { return Ok(()); }
    debug!(table, rows = records.len(), "insert_batch: sending");
    let mut ins = client.insert::<OcsfRecord>(table)
        .with_context(|| format!("open insert for {table}"))?;
    for rec in &records {
        ins.write(rec).await.with_context(|| format!("write row → {table}"))?;
    }
    ins.end().await.with_context(|| format!("end insert → {table}"))?;
    Ok(())
}

async fn flush_all(
    client:       &Client,
    url:          &str,
    user:         &str,
    password:     &str,
    db:           &str,
    ttl_days:     Option<u32>,
    batches:      &mut BatchMap,
    known_tables: &mut HashSet<String>,
) {
    let work: Vec<(String, Vec<OcsfRecord>)> = batches
        .iter_mut()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| (k.clone(), std::mem::take(v)))
        .collect();
    batches.retain(|_, v| !v.is_empty());

    if work.is_empty() {
        trace!("flush_all: nothing pending");
        return;
    }
    let total_rows: usize = work.iter().map(|(_, v)| v.len()).sum();
    debug!(tables = work.len(), rows = total_rows, "flush_all: start");

    for (table, records) in work {
        if !known_tables.contains(&table) {
            match ensure_table(client, url, user, password, db, &table, ttl_days).await {
                Ok(_)  => { known_tables.insert(table.clone()); info!("table ready: {table}"); }
                Err(e) => { error!("ensure_table {table}: {e:#}"); continue; }
            }
        }
        let n = records.len();
        match insert_batch(client, &table, records).await {
            Ok(_)  => info!(rows = n, table = %table, "flush ok"),
            Err(e) => error!(table = %table, "insert failed: {e:#}"),
        }
    }
}

// ─── Config hot-reload (mtime polling) ───────────────────────────────────────

fn file_mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).ok().and_then(|m| m.modified().ok())
}

async fn config_watcher_task(
    path:     PathBuf,
    mappings: Arc<RwLock<CustomMappings>>,
) {
    let mut last = file_mtime(&path);
    let mut tick = interval(Duration::from_secs(CONFIG_POLL_SECS));
    loop {
        tick.tick().await;
        let cur = file_mtime(&path);
        if cur != last {
            last = cur;
            match CustomMappings::load(&path) {
                Ok(new) => {
                    let ver = new.ocsf_version.clone();
                    let renames = new.ocsf_renames.clone();
                    let mut g = match mappings.write() {
                        Ok(g)  => g,
                        Err(e) => {
                            // Poisoned means another thread panicked while writing;
                            // recover the guard so the service keeps running.
                            error!("field_mappings RwLock poisoned — recovering: {e}");
                            e.into_inner()
                        }
                    };
                    for (old, new_col) in &renames {
                        warn!(
                            "OCSF schema rename: `{old}` → `{new_col}`. \
                             Run: ALTER TABLE <db>.<table> \
                             RENAME COLUMN `{old}` TO `{new_col}`;"
                        );
                    }
                    *g = new;
                    info!("field_mappings.toml reloaded (OCSF {ver})");
                }
                Err(e) => warn!("field_mappings.toml reload: {e:#}"),
            }
        }
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────
//
// Architecture
// ────────────
//   [reader_task]  reads alerts.json line-by-line, tracking byte offset.
//        │ bounded mpsc channel (CHANNEL_CAP lines)
//        │ → blocks when full  ← backpressure: ClickHouse slow? reader pauses.
//   [main loop]   receives lines, transforms, batches, flushes on size or timer.
//        │ after every successful flush: saves committed offset to state file.
//   [config watcher] hot-reloads field_mappings.toml every 10 s.
//
// Restart guarantees
// ──────────────────
//   • Saved offset = last committed byte → seek to it instantly (no replay of
//     already-inserted rows in the normal-stop case).
//   • inode check → rotation-while-stopped detected at startup; resumes on
//     the new file from offset 0 (nothing skipped).
//   • Crash: at-least-once — at most CHANNEL_CAP + BATCH_SIZE lines re-processed.
//
// Graceful shutdown (SIGTERM / SIGINT)
// ──────────────────────────────────
//   Signal received → reader task exit signalled → channel drained →
//   remaining batch flushed → final offset saved → clean exit.

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| {
                    // RUST_LOG not set or invalid — fall back to info.
                    // Users can set:  RUST_LOG=info          → standard production output
                    //                 RUST_LOG=debug         → per-alert transform + flush details
                    //                 RUST_LOG=trace         → per-line reader events (very verbose)
                    tracing_subscriber::EnvFilter::new("info")
                }),
        )
        .with_target(false)   // omit the module path (wazuh_ocsf_etl) from every line
        .with_thread_ids(false)
        .init();

    let cfg = Arc::new(AppConfig::from_env());

    // ── Startup configuration sanity checks ──────────────────────────────
    if cfg.batch_size == 0 {
        // batch_size=0 would make the size-trigger condition (len >= 0) fire on
        // every single row, which is technically fine but extremely inefficient.
        warn!("BATCH_SIZE=0 — every row will be flushed individually (very slow). \
               Set BATCH_SIZE to at least 100.");
    }
    if cfg.flush_interval_secs == 0 {
        warn!("FLUSH_INTERVAL_SECS=0 — the timer will fire as fast as the tokio \
               scheduler allows. Set to at least 1.");
    }
    if cfg.channel_cap < cfg.batch_size * 2 {
        warn!(
            "CHANNEL_CAP ({}) < BATCH_SIZE ({}) × 2 — the reader will be forced to pause \
             during every ClickHouse flush. Recommended minimum: {}",
            cfg.channel_cap, cfg.batch_size, cfg.batch_size * 10
        );
    }

    // ── State: load saved byte offset + resolve effective start position ──────
    //
    // Decision matrix:
    //
    //  State file present (offset > 0)?   YES → seek to saved offset.
    //                                           Single lseek() syscall — instant
    //                                           regardless of file size.
    //
    //  State file absent (first run)?     SEEK_TO_END_ON_FIRST_RUN=true (default)
    //                                           → seek to END of file.
    //                                           A 50 GB alerts.json is not replayed.
    //                                           Only NEW lines written after this
    //                                           start are processed.
    //
    //                                     SEEK_TO_END_ON_FIRST_RUN=false
    //                                           → start from offset 0.
    //                                           Full historical replay — useful
    //                                           when you want to backfill ClickHouse
    //                                           from a fresh install.
    //
    //  Saved offset > current file size?  File was truncated/rotated between
    //                                     runs but state was not updated (e.g.
    //                                     forceful kill right after rotation).
    //                                     → seek to 0 on the current file.
    let state_store = Arc::new(StateStore::new(cfg.state_file.clone()));
    let saved_state = state_store.load();

    // Current file size for display + sanity checking (non-fatal if file absent).
    let file_size: u64 = std::fs::metadata(&cfg.alerts_file)
        .map(|m| m.len()).unwrap_or(0);
    let current_inode: u64 = std::fs::metadata(&cfg.alerts_file)
        .map(|m| std::os::unix::fs::MetadataExt::ino(&m)).unwrap_or(0);

    let is_first_run = saved_state.offset == 0 && saved_state.inode == 0;

    let start_offset: u64 = if !is_first_run {
        // We have a prior state.  Check if offset is still valid.
        if saved_state.inode != 0 && saved_state.inode != current_inode {
            // Inode changed between runs — handled inside reader_task (opens at 0).
            // Pass the saved offset; reader_task will reset to 0 on inode mismatch.
            saved_state.offset
        } else if saved_state.offset > file_size {
            // Offset past EOF — file was truncated while stopped.
            warn!("State offset {} > file size {} — file was truncated. Starting from 0.",
                  saved_state.offset, file_size);
            0
        } else {
            saved_state.offset
        }
    } else if cfg.seek_to_end_on_first_run {
        // First ever run: jump to current end — no 50 GB replay.
        file_size
    } else {
        // SEEK_TO_END_ON_FIRST_RUN=false: full historical backfill from byte 0.
        0
    };

    let start_state = TailState { inode: current_inode, offset: start_offset };

    // If this is a first-run-at-end start, persist the offset immediately so
    // that if the process is killed before the first flush the position is not lost.
    if is_first_run && start_offset > 0 {
        let _ = state_store.save(&start_state);
    }

    // ── Custom field mappings (non-fatal if absent) ────────────────────────
    let initial_mappings = CustomMappings::load(&cfg.mappings_file)
        .unwrap_or_else(|e| {
            warn!("field_mappings.toml not loaded ({e:#}), using defaults");
            CustomMappings::default()
        });

    info!("=== Wazuh → OCSF → ClickHouse ETL ===");
    info!("  alerts_file      : {} (size: {:.1} MB)",
          cfg.alerts_file, file_size as f64 / 1_048_576.0);
    info!("  start_offset     : {}  ({:.1} MB to process on startup)",
          start_offset,
          (file_size.saturating_sub(start_offset)) as f64 / 1_048_576.0);
    if is_first_run {
        if cfg.seek_to_end_on_first_run {
            info!("  first_run_mode   : TAIL (start from end — existing data skipped)");
            info!("  └ set SEEK_TO_END_ON_FIRST_RUN=false to replay history from the start");
        } else {
            info!("  first_run_mode   : REPLAY (reading from byte 0 — full historical ingest)");
        }
    } else {
        let gap = file_size.saturating_sub(start_offset);
        if gap > 0 {
            info!("  catch_up         : {:.1} MB written while service was stopped",
                  gap as f64 / 1_048_576.0);
        }
    }
    info!("  state_file       : {}", cfg.state_file.display());
    info!("  seek_end_on_first : {}", cfg.seek_to_end_on_first_run);
    info!("  input_mode       : {}", match cfg.input_mode {
        InputMode::File   => format!("FILE  ({})", cfg.alerts_file),
        InputMode::ZeroMq => format!("ZEROMQ  ({})", cfg.zeromq_uri),
    });
    info!("  batch_size       : {}   flush: every {}s   channel_cap: {} (~{} MB max in-flight)",
          cfg.batch_size, cfg.flush_interval_secs, cfg.channel_cap, cfg.channel_cap / 1024);
    info!("  special_locations: {:?}", cfg.special_locations);
    info!("  data_ttl_days    : {:?}", cfg.data_ttl_days);
    info!("  ocsf_version     : {}", initial_mappings.ocsf_version);
    info!("  custom_mappings  : {} rule(s)", initial_mappings.field_map.len());

    for (old, new_col) in &initial_mappings.ocsf_renames {
        warn!("OCSF rename pending: `{old}` → `{new_col}`. \
               Run: ALTER TABLE <db>.<table> RENAME COLUMN `{old}` TO `{new_col}`;");
    }

    let custom_mappings: Arc<RwLock<CustomMappings>> =
        Arc::new(RwLock::new(initial_mappings));

    let client = Client::default()
        .with_url(&cfg.clickhouse_url)
        .with_user(&cfg.clickhouse_user)
        .with_password(&cfg.clickhouse_password)
        .with_database(&cfg.clickhouse_db);

    // ── Spawn: config hot-reload watcher ──────────────────────────────────
    tokio::spawn(config_watcher_task(
        cfg.mappings_file.clone(),
        Arc::clone(&custom_mappings),
    ));

    // ── Bounded channel between reader and processor ───────────────────────
    // Sender is moved into reader_task. Dropping it (on reader exit) closes
    // the channel, causing rx.recv() to return None → graceful drain + exit.
    let (tx, mut rx) = mpsc::channel::<(u64, String)>(cfg.channel_cap);

    // ── Shutdown token: dropped to signal the reader to stop ──────────────
    // We wrap tx in an Option so we can drop it explicitly on signal.
    let mut tx_opt: Option<mpsc::Sender<(u64, String)>> = Some(tx);

    // ── Spawn: reader task (FILE or ZEROMQ) ──────────────────────────────
    {
        let tx_reader = tx_opt.take().expect("tx_opt is always Some at this point");
        match cfg.input_mode {
            InputMode::File => {
                let alerts_path = PathBuf::from(&cfg.alerts_file);
                tokio::spawn(reader_task(alerts_path, start_state.clone(), tx_reader));
            }
            InputMode::ZeroMq => {
                let uri = cfg.zeromq_uri.clone();
                tokio::spawn(zmq_reader_task(uri, tx_reader));
            }
        }
    }

    // ── Processing state (local to main loop — no mutex needed) ─────────
    let mut batches:      BatchMap        = HashMap::new();
    let mut known_tables: HashSet<String> = HashSet::new();
    let mut current_offset: u64 = start_state.offset;

    // Timer-flush tick.
    let mut flush_tick = interval(Duration::from_secs(cfg.flush_interval_secs));
    flush_tick.tick().await; // consume the immediate first tick

    // ── SIGTERM / SIGINT handlers ─────────────────────────────────────────
    // We use a wrapper future so the select! arms stay cfg-free.
    let mut shutdown = std::pin::pin!(shutdown_signal());
    let mut shutting_down = false;

    // ── Main event loop ───────────────────────────────────────────────────
    loop {
        tokio::select! {
            // ── New line from reader ───────────────────────────────────────
            msg = rx.recv() => {
                match msg {
                    None => {
                        info!("Reader closed — flushing final batch…");
                        do_flush(&client, &cfg, &mut batches, &mut known_tables,
                                 &state_store, current_offset).await;
                        break;
                    }
                    Some((offset, raw)) => {
                        current_offset = offset;
                        let record_opt = {
                            // Recover from a poisoned RwLock (only possible if a thread
                            // panicked while holding a write lock — extremely unlikely).
                            let guard = match custom_mappings.read() {
                                Ok(g)  => g,
                                Err(e) => {
                                    error!("custom_mappings RwLock poisoned — recovering: {e}");
                                    e.into_inner()
                                }
                            };
                            transform(&raw, &cfg.clickhouse_db, &cfg.special_locations, &guard)
                        };
                        if let Some((table, record)) = record_opt {
                            let bucket = batches.entry(table.clone()).or_default();
                            bucket.push(record);
                            if bucket.len() >= cfg.batch_size {
                                // Use debug! — flush_all already logs info! with row count
                                debug!(table = %table, rows = cfg.batch_size, "batch-size flush triggered");
                                do_flush(&client, &cfg, &mut batches, &mut known_tables,
                                         &state_store, current_offset).await;
                            }
                        }
                    }
                }
            }

            // ── Periodic timer flush ──────────────────────────────────────
            _ = flush_tick.tick() => {
                let pending: usize = batches.values().map(|v| v.len()).sum();
                if pending > 0 {
                    debug!(rows = pending, tables = batches.len(), "timer flush triggered");
                    do_flush(&client, &cfg, &mut batches, &mut known_tables,
                             &state_store, current_offset).await;
                } else {
                    trace!("timer tick: no pending rows");
                }
            }

            // ── Graceful shutdown (SIGTERM or SIGINT) ─────────────────────
            _ = &mut shutdown, if !shutting_down => {
                info!("Shutdown signal — draining channel and flushing…");
                shutting_down = true;
                // Close the receive side: any already-queued messages can still
                // be recv()'d, but no new messages can be sent.  The next time
                // rx.recv() returns None we do the final flush and break.
                rx.close();
            }
        }
    }

    info!("Shutdown complete. Committed offset={current_offset}");
    Ok(())
}

/// Resolves when SIGTERM **or** SIGINT is received — whichever comes first.
/// Used as a single pin-able future in the main select! loop.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            // Extremely unlikely — only happens if the OS refuses to set up the handler.
            error!("Ctrl-C signal handler error: {e:#} — graceful shutdown via Ctrl-C unavailable");
            // Park forever rather than incorrectly triggering a shutdown.
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => { sig.recv().await; }
            Err(e) => {
                error!("Cannot install SIGTERM handler: {e:#} — SIGTERM will not trigger graceful shutdown");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c   => {}
        _ = terminate => {}
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn no_custom() -> CustomMappings { CustomMappings::default() }

    // ── Sanitise ─────────────────────────────────────────────────────────

    #[test]
    fn sanitize_path() {
        assert_eq!(sanitize_name("/var/log/auth.log"), "var_log_auth_log");
    }
    #[test]
    fn sanitize_dashes_dots() {
        assert_eq!(sanitize_name("agent-01.corp.local"), "agent_01_corp_local");
    }

    // ── Routing ──────────────────────────────────────────────────────────

    #[test]
    fn route_default_agent_name() {
        let t = routing_table("db", "linux-srv-01", "/var/log/auth.log", &[]);
        assert_eq!(t, "db.ocsf_linux_srv_01");
    }
    #[test]
    fn route_special_location() {
        let sp = vec!["aws-cloudtrail".to_string()];
        let t = routing_table("db", "any-agent", "aws-cloudtrail", &sp);
        assert_eq!(t, "db.ocsf_aws_cloudtrail");
    }
    #[test]
    fn route_loc_not_in_special_uses_agent() {
        let sp = vec!["aws-cloudtrail".to_string()];
        let t = routing_table("db", "win-dc-01", "EventChannel", &sp);
        assert_eq!(t, "db.ocsf_win_dc_01");
    }
    #[test]
    fn route_empty_agent_fallback() {
        let t = routing_table("db", "", "unknown", &[]);
        assert_eq!(t, "db.ocsf_unknown_agent");
    }

    // ── Severity ─────────────────────────────────────────────────────────

    #[test]
    fn severity_bands() {
        // OCSF 1.7.0 severity_id: 0=Unknown 1=Informational 2=Low 3=Medium
        //   4=High 5=Critical 99=Other.  No value 6 ("Fatal") exists.
        // Wazuh max level is 15; maps to Critical (5).
        let cases = [(0,"Unknown"),(1,"Informational"),(4,"Low"),
                     (7,"Medium"),(10,"High"),(13,"Critical"),(15,"Critical")];
        for (lvl, label) in cases { assert_eq!(map_severity(lvl).1, label, "level={lvl}"); }
    }
    #[test]
    fn severity_ids_are_valid_ocsf() {
        // All severity_id values must be in the OCSF 1.7.0 enum: 0-5 and 99
        let valid: std::collections::HashSet<u8> = [0,1,2,3,4,5,99].into();
        for level in 0u64..=20 {
            let (id, _) = map_severity(level);
            assert!(valid.contains(&id), "severity_id={id} for level={level} is not in OCSF 1.7.0 enum");
        }
    }

    // ── JSON helpers ─────────────────────────────────────────────────────

    #[test]
    fn jpath_nested() {
        let v = serde_json::json!({"win":{"eventdata":{"ipAddress":"1.2.3.4"}}});
        assert_eq!(jpath(&v, "win.eventdata.ipAddress"), "1.2.3.4");
        assert_eq!(jpath(&v, "win.eventdata.missing"), "");
    }
    #[test]
    fn get_data_field_literal_key() {
        // Literal dot-in-key (auditd flat output)
        let v = serde_json::json!({"audit.command": "ls"});
        assert_eq!(get_data_field(&v, "audit.command"), "ls");
    }
    #[test]
    fn get_data_field_nested_fallback() {
        // Normal nested path
        let v = serde_json::json!({"audit": {"command": "ls"}});
        assert_eq!(get_data_field(&v, "audit.command"), "ls");
    }
    #[test]
    fn first_port_string_and_number() {
        let v = serde_json::json!({"s":"8080","n":443,"zero":"0"});
        assert_eq!(first_port(&v, &["s"]),    8080u16);
        assert_eq!(first_port(&v, &["n"]),    443u16);
        assert_eq!(first_port(&v, &["zero"]), 0u16);
    }
    #[test]
    fn first_u64_bytes() {
        let v = serde_json::json!({"rcvdbyte": "102400", "sentbyte": 204800u64});
        assert_eq!(first_u64(&v, BYTES_IN),  102400u64);
        assert_eq!(first_u64(&v, BYTES_OUT), 204800u64);
    }

    // ── Syslog / generic Linux alert ─────────────────────────────────────

    #[test]
    fn transform_syslog() {
        let raw = r#"{
            "@timestamp":"2024-03-01T12:00:00Z",
            "agent":  {"id":"001","name":"linux-srv-01","ip":"10.0.0.1"},
            "rule":   {"id":"5503","description":"SSH brute force","level":10,
                       "groups":["syslog","sshd"],
                       "mitre":{"technique":["T1110"],"id":["T1110"],"tactic":["credential-access"]}},
            "manager":{"name":"wazuh-mgr"},
            "decoder":{"name":"sshd"},
            "location":"/var/log/auth.log",
            "data":{"srcip":"203.0.113.5","srcport":"55123","dstport":"22",
                    "srcuser":"root","protocol":"tcp"}
        }"#;
        let (tbl, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(tbl,             "db.ocsf_linux_srv_01");
        assert_eq!(rec.src_ip,      "203.0.113.5");
        assert_eq!(rec.src_port,    55123u16);
        assert_eq!(rec.dst_port,    22u16);
        assert_eq!(rec.actor_user,  "root");
        assert_eq!(rec.network_protocol, "tcp");
        assert_eq!(rec.severity_id, 4);
        assert!(rec.attack_id.contains("T1110"));
        assert_eq!(rec.decoder_name, "sshd");
    }

    // ── Windows Event Channel ─────────────────────────────────────────────

    #[test]
    fn transform_windows_eventchannel() {
        let raw = r#"{
            "@timestamp":"2024-03-01T12:00:00Z",
            "agent":  {"id":"002","name":"win-dc-01","ip":"10.0.1.5"},
            "rule":   {"id":"60106","description":"Windows login failure","level":5,
                       "groups":["windows","authentication_failed"]},
            "manager":{"name":"wazuh-mgr"},
            "decoder":{"name":"windows_eventchannel"},
            "location":"EventChannel",
            "data":{
                "win":{
                    "system":{"computer":"WIN-DC-01","eventID":"4625"},
                    "eventdata":{
                        "ipAddress":"192.168.1.100",
                        "ipPort":"0",
                        "targetUserName":"Administrator",
                        "subjectDomainName":"CORP",
                        "workstationName":"WORKSTATION01",
                        "status":"0xC000006D"
                    }
                }
            }
        }"#;
        // EventChannel is NOT in special_locs → per-agent table
        let (tbl, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(tbl, "db.ocsf_win_dc_01");
        assert_eq!(rec.src_ip,      "192.168.1.100");
        assert_eq!(rec.actor_user,  "Administrator");
        assert_eq!(rec.domain,      "CORP");
        assert_eq!(rec.src_hostname,"WIN-DC-01");
        assert_eq!(rec.status,      "0xC000006D");
        assert_eq!(rec.severity_id, 2);  // level 5 → Low
    }

    // ── Suricata / IDS ────────────────────────────────────────────────────

    #[test]
    fn transform_suricata() {
        let raw = r#"{
            "@timestamp":"2024-03-01T12:05:00Z",
            "agent":  {"id":"003","name":"ids-sensor","ip":"10.0.2.1"},
            "rule":   {"id":"86601","description":"Suricata: ET SCAN","level":8,
                       "groups":["ids","suricata"]},
            "manager":{"name":"wazuh-mgr"},
            "decoder":{"name":"json"},
            "location":"/var/log/suricata/eve.json",
            "data":{
                "alert":{
                    "action":"blocked","src_ip":"198.51.100.7",
                    "dest_ip":"10.0.2.1","src_port":12345,
                    "dest_port":22,"proto":"TCP"
                },
                "bytes":1024
            }
        }"#;
        let (tbl, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(tbl, "db.ocsf_ids_sensor");
        assert_eq!(rec.src_ip,           "198.51.100.7");
        assert_eq!(rec.dst_port,         22u16);
        assert_eq!(rec.network_protocol, "TCP");
        assert_eq!(rec.action,           "blocked");
        assert_eq!(rec.bytes_in,         1024u64);
    }

    // ── FortiGate firewall log ─────────────────────────────────────────────

    #[test]
    fn transform_fortigate() {
        let raw = r#"{
            "@timestamp":"2024-03-01T12:10:00Z",
            "agent":  {"id":"004","name":"fortinet-fw","ip":"10.0.3.1"},
            "rule":   {"id":"81600","description":"FortiGate: traffic blocked","level":7,
                       "groups":["firewall","fortigate"]},
            "manager":{"name":"wazuh-mgr"},
            "decoder":{"name":"fortigate-traffic"},
            "location":"syslog",
            "data":{
                "srcip":"10.10.10.5","dstip":"8.8.8.8",
                "srcport":"49152","dstport":"443",
                "srcintf":"internal","dstintf":"wan1",
                "action":"deny",
                "proto":"tcp",
                "rcvdbyte":"0","sentbyte":"512",
                "transip":"203.0.113.1",
                "transport":"49200",
                "nat_dstip":"8.8.4.4"
            }
        }"#;
        let (tbl, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(tbl,               "db.ocsf_fortinet_fw");
        assert_eq!(rec.src_ip,        "10.10.10.5");
        assert_eq!(rec.dst_ip,        "8.8.8.8");
        assert_eq!(rec.dst_port,      443u16);
        assert_eq!(rec.nat_src_ip,    "203.0.113.1");
        assert_eq!(rec.nat_src_port,  49200u16);
        assert_eq!(rec.nat_dst_ip,    "8.8.4.4");
        assert_eq!(rec.interface_in,  "internal");
        assert_eq!(rec.interface_out, "wan1");
        assert_eq!(rec.action,        "deny");
        assert_eq!(rec.bytes_out,     512u64);
    }

    // ── AWS CloudTrail (via special location) ─────────────────────────────

    #[test]
    fn transform_aws_cloudtrail_special_loc() {
        let raw = r#"{
            "@timestamp":"2024-03-01T12:15:00Z",
            "agent":  {"id":"000","name":"wazuh-mgr","ip":"10.0.4.1"},
            "rule":   {"id":"80202","description":"AWS: Login failure","level":6,
                       "groups":["amazon","aws"]},
            "manager":{"name":"wazuh-mgr"},
            "decoder":{"name":"json"},
            "location":"aws-cloudtrail",
            "data":{
                "aws":{
                    "sourceIPAddress":"52.1.2.3",
                    "eventName":"ConsoleLogin",
                    "errorCode":"Failed authentication",
                    "userIdentity":{
                        "userName":"jdoe",
                        "accountId":"123456789"
                    }
                }
            }
        }"#;
        let sp = vec!["aws-cloudtrail".to_string()];
        let (tbl, rec) = transform(raw, "db", &sp, &no_custom()).unwrap();
        // Special location → location-named table
        assert_eq!(tbl,             "db.ocsf_aws_cloudtrail");
        assert_eq!(rec.src_ip,      "52.1.2.3");
        assert_eq!(rec.actor_user,  "jdoe");
        assert_eq!(rec.domain,      "123456789");
        assert_eq!(rec.action,      "ConsoleLogin");
        assert_eq!(rec.status,      "Failed authentication");
    }

    // ── Auditd (literal dotted keys) ──────────────────────────────────────

    #[test]
    // Wazuh auditd decoder outputs nested JSON objects from dotted <order> fields:
    //   <order>audit.command, audit.pid, audit.auid</order>
    // produces: data.audit.command (nested), NOT data["audit.command"] (literal).
    fn transform_auditd_nested() {
        let raw = r#"{
            "@timestamp":"2024-03-01T12:20:00Z",
            "agent":  {"id":"005","name":"audit-host","ip":"10.0.5.1"},
            "rule":   {"id":"80791","description":"Auditd: command run","level":3,
                       "groups":["audit","linux"]},
            "manager":{"name":"wazuh-mgr"},
            "decoder":{"name":"auditd"},
            "location":"/var/log/audit/audit.log",
            "data":{
                "audit":{
                    "command":"passwd",
                    "pid":"1234",
                    "auid":"root",
                    "exe":"/usr/bin/passwd"
                }
            }
        }"#;
        let (tbl, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(tbl, "db.ocsf_audit_host");
        // audit.exe takes priority over audit.command (full path is more useful)
        assert_eq!(rec.process_name, "/usr/bin/passwd");
        // audit.auid → actor_user (nested path)
        assert_eq!(rec.actor_user,   "root");
    }

    // ── Custom field mapping ──────────────────────────────────────────────

    #[test]
    fn transform_custom_fills_empty_src_ip() {
        let raw = r#"{
            "agent":{"id":"006","name":"myapp-host","ip":"10.0.6.1"},
            "rule": {"id":"1","description":"test","level":3},
            "data": {"myapp.client_addr":"1.2.3.4"}
        }"#;
        let mut cm = no_custom();
        cm.field_map.insert("myapp.client_addr".into(), "src_ip".into());
        let (_, rec) = transform(raw, "db", &[], &cm).unwrap();
        assert_eq!(rec.src_ip, "1.2.3.4");
    }
    #[test]
    fn transform_custom_wont_override_existing_src_ip() {
        let raw = r#"{
            "agent":{"id":"007","name":"test","ip":""},
            "rule": {"id":"1","description":"t","level":3},
            "data": {"srcip":"5.5.5.5","myapp.other_ip":"9.9.9.9"}
        }"#;
        // built-in srcip should win; custom should not override non-empty field
        let mut cm = no_custom();
        cm.field_map.insert("myapp.other_ip".into(), "src_ip".into());
        let (_, rec) = transform(raw, "db", &[], &cm).unwrap();
        assert_eq!(rec.src_ip, "5.5.5.5");
    }
    #[test]
    fn transform_custom_to_extension() {
        let raw = r#"{
            "agent":{"id":"008","name":"test","ip":""},
            "rule": {"id":"1","description":"t","level":3},
            "data": {"myapp.score":"99"}
        }"#;
        let mut cm = no_custom();
        cm.field_map.insert("myapp.score".into(), "threat_score".into());
        let (_, rec) = transform(raw, "db", &[], &cm).unwrap();
        let ext: Value = serde_json::from_str(&rec.extensions).unwrap();
        assert_eq!(ext["threat_score"].as_str(), Some("99"));
    }

    // ── Lossless: event_data + unmapped ───────────────────────────────────

    #[test]
    fn transform_zero_data_loss() {
        let raw = r#"{
            "agent":          {"id":"009","name":"test","ip":""},
            "rule":           {"id":"1","description":"t","level":3},
            "custom_toplevel":"should_be_in_unmapped",
            "data":           {"known_field":"val","extra_data":"extra"}
        }"#;
        let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        // raw top-level unknown keys → unmapped
        let u: Value = serde_json::from_str(&rec.unmapped).unwrap();
        assert!(u.get("custom_toplevel").is_some(), "missing custom_toplevel");
        // all data.* → event_data
        assert!(rec.event_data.contains("known_field"));
        assert!(rec.event_data.contains("extra_data"));
    }
    #[test]
    fn transform_invalid_json_returns_none() {
        assert!(transform("{{{bad", "db", &[], &no_custom()).is_none());
    }
    #[test]
    fn transform_missing_timestamp_fallback() {
        let raw = r#"{"rule":{"id":"1","description":"t","level":3}}"#;
        let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert!(rec.time > 0);
    }

    // ── OCSF classify_event ───────────────────────────────────────────────

    #[test]
    fn classify_sshd_is_authentication() {
        let c = classify_event(&["sshd", "authentication_failed"], "sshd", "/var/log/auth.log");
        assert_eq!(c.class_uid,    3002);
        assert_eq!(c.class_name,   "Authentication");
        assert_eq!(c.category_uid, 3);
    }
    #[test]
    fn classify_pam_is_authentication() {
        let c = classify_event(&["pam"], "pam", "/var/log/syslog");
        assert_eq!(c.class_uid, 3002);
    }
    #[test]
    fn classify_syscheck_is_file_activity() {
        let c = classify_event(&["syscheck", "syscheck_file"], "syscheck_file", "syscheck");
        assert_eq!(c.class_uid,  1001);
        assert_eq!(c.class_name, "File System Activity");
    }
    #[test]
    fn classify_sysmon_process_is_process_activity() {
        let c = classify_event(&["sysmon", "sysmon_process", "process_creation"], "sysmon", "EventChannel");
        assert_eq!(c.class_uid,  1006);
        assert_eq!(c.class_name, "Process Activity");
    }
    #[test]
    fn classify_vuln_detector() {
        let c = classify_event(&["vulnerability-detector"], "vulnerability-detector", "");
        assert_eq!(c.class_uid, 2002);
        assert_eq!(c.class_name, "Vulnerability Finding");
    }
    #[test]
    fn classify_sca_is_compliance() {
        let c = classify_event(&["sca"], "sca", "");
        assert_eq!(c.class_uid, 2003);
        assert_eq!(c.class_name, "Compliance Finding");
    }
    #[test]
    fn classify_adduser_is_account_change() {
        let c = classify_event(&["adduser", "linux_account"], "adduser", "");
        assert_eq!(c.class_uid, 3001);
        assert_eq!(c.class_name, "Account Change");
    }
    #[test]
    fn classify_nginx_is_http() {
        let c = classify_event(&["web", "web-log"], "nginx", "/var/log/nginx/access.log");
        assert_eq!(c.class_uid,  4002);
        assert_eq!(c.class_name, "HTTP Activity");
    }
    #[test]
    fn classify_access_log_location_is_http() {
        // decoder unknown, but location ends in access.log
        let c = classify_event(&["syslog"], "json", "/srv/app/access.log");
        assert_eq!(c.class_uid, 4002);
    }
    #[test]
    fn classify_fortigate_is_network() {
        let c = classify_event(&["firewall", "fortigate"], "fortigate-traffic", "syslog");
        assert_eq!(c.class_uid,  4001);
        assert_eq!(c.class_name, "Network Activity");
    }
    #[test]
    fn classify_suricata_is_network() {
        let c = classify_event(&["ids", "suricata"], "json", "/var/log/suricata/eve.json");
        assert_eq!(c.class_uid, 4001);
    }
    #[test]
    fn classify_dns_query() {
        let c = classify_event(&["dns"], "named", "");
        assert_eq!(c.class_uid, 4003);
        assert_eq!(c.class_name, "DNS Activity");
    }
    #[test]
    fn classify_dhcp() {
        let c = classify_event(&["dhcp"], "dhcpd", "");
        assert_eq!(c.class_uid, 4004);
    }
    #[test]
    fn classify_default_is_detection_finding() {
        let c = classify_event(&["rootkit", "windows"], "rootcheck", "");
        assert_eq!(c.class_uid,  2004);
        assert_eq!(c.class_name, "Detection Finding");
    }

    // ── class_uid in transform round-trips ───────────────────────────────

    #[test]
    fn transform_syslog_has_auth_class() {
        let raw = r#"{
            "@timestamp":"2024-03-01T12:00:00Z",
            "agent":  {"id":"001","name":"linux-srv","ip":"10.0.0.1"},
            "rule":   {"id":"5503","description":"SSH brute","level":10,
                       "groups":["syslog","sshd","authentication_failed"]},
            "manager":{"name":"mgr"},
            "decoder":{"name":"sshd"},
            "location":"/var/log/auth.log"
        }"#;
        let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(rec.class_uid,    3002);
        assert_eq!(rec.class_name,   "Authentication");
        assert_eq!(rec.category_uid, 3);
        assert_eq!(rec.category_name,"Identity & Access Management");
    }
    #[test]
    fn transform_suricata_has_network_class() {
        let raw = r#"{
            "@timestamp":"2024-03-01T12:00:00Z",
            "agent":  {"id":"002","name":"ids","ip":"10.0.0.2"},
            "rule":   {"id":"86600","description":"IDS alert","level":7,
                       "groups":["ids","suricata"]},
            "manager":{"name":"mgr"},
            "decoder":{"name":"json"},
            "location":"/var/log/suricata/eve.json"
        }"#;
        let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(rec.class_uid, 4001);
        assert_eq!(rec.category_uid, 4);
    }

    // ── OCSF activity_id correctness per class ───────────────────────────

    /// type_uid = class_uid * 100 + activity_id — verify no phantom values.
    #[test]
    fn type_uid_is_class_times_100_plus_activity() {
        // Authentication Logon → type_uid = 300201
        let raw = r#"{
            "@timestamp":"2024-01-01T00:00:00Z",
            "agent":{"id":"1","name":"host","ip":""},
            "rule":{"id":"1","description":"t","level":3,"groups":["sshd","authentication_failed"]},
            "decoder":{"name":"sshd"}
        }"#;
        let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(rec.class_uid, 3002);
        assert_eq!(rec.activity_id, 1, "Logon = 1");
        assert_eq!(rec.activity_name, "Logon");
        assert_eq!(rec.type_uid, 3002 * 100 + 1, "type_uid must be class_uid*100+activity_id");
    }

    #[test]
    fn network_activity_allow_maps_to_open() {
        let raw = r#"{
            "@timestamp":"2024-01-01T00:00:00Z",
            "agent":{"id":"1","name":"fw","ip":""},
            "rule":{"id":"1","description":"t","level":3,"groups":["firewall","fortigate"]},
            "decoder":{"name":"fortigate-traffic"},
            "data":{"srcip":"1.2.3.4","action":"allow"}
        }"#;
        let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(rec.class_uid,     4001);
        assert_eq!(rec.activity_id,   1, "allow → Open(1)");
        assert_eq!(rec.activity_name, "Open");
        assert_eq!(rec.type_uid,      400101);
    }

    #[test]
    fn network_activity_deny_maps_to_refuse() {
        let raw = r#"{
            "@timestamp":"2024-01-01T00:00:00Z",
            "agent":{"id":"1","name":"fw","ip":""},
            "rule":{"id":"1","description":"t","level":3,"groups":["firewall","fortigate"]},
            "decoder":{"name":"fortigate-traffic"},
            "data":{"srcip":"1.2.3.4","action":"deny"}
        }"#;
        let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(rec.activity_id,   5, "deny → Refuse(5)");
        assert_eq!(rec.activity_name, "Refuse");
        assert_eq!(rec.type_uid,      400105);
    }

    #[test]
    fn network_activity_no_action_is_traffic() {
        let raw = r#"{
            "@timestamp":"2024-01-01T00:00:00Z",
            "agent":{"id":"1","name":"fw","ip":""},
            "rule":{"id":"1","description":"t","level":3,"groups":["firewall","iptables"]},
            "decoder":{"name":"iptables"}
        }"#;
        let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(rec.class_uid,   4001);
        assert_eq!(rec.activity_id, 6, "no action → Traffic(6)");
        assert_eq!(rec.activity_name, "Traffic");
    }

    #[test]
    fn dhcp_activity_id_is_assign() {
        let raw = r#"{
            "@timestamp":"2024-01-01T00:00:00Z",
            "agent":{"id":"1","name":"dhcp-srv","ip":""},
            "rule":{"id":"1","description":"t","level":3,"groups":["dhcp"]},
            "decoder":{"name":"dhcpd"}
        }"#;
        let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(rec.class_uid,     4004);
        assert_eq!(rec.activity_id,   1, "DHCP default → Assign(1)");
        assert_eq!(rec.activity_name, "Assign");
        assert_eq!(rec.type_uid,      400401);
    }

    #[test]
    fn fim_added_is_create() {
        let raw = r#"{
            "@timestamp":"2024-01-01T00:00:00Z",
            "agent":{"id":"1","name":"host","ip":""},
            "rule":{"id":"550","description":"FIM","level":7,"groups":["syscheck","syscheck_file"]},
            "decoder":{"name":"syscheck"},
            "syscheck":{"event":"added","path":"/etc/passwd"}
        }"#;
        let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(rec.class_uid,     1001);
        assert_eq!(rec.activity_id,   1, "added → Create(1)");
        assert_eq!(rec.activity_name, "Create");
    }

    #[test]
    fn fim_modified_is_update() {
        let raw = r#"{
            "@timestamp":"2024-01-01T00:00:00Z",
            "agent":{"id":"1","name":"host","ip":""},
            "rule":{"id":"550","description":"FIM","level":7,"groups":["syscheck","syscheck_file"]},
            "decoder":{"name":"syscheck"},
            "syscheck":{"event":"modified","path":"/etc/passwd"}
        }"#;
        let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(rec.activity_id,   3, "modified → Update(3)");
        assert_eq!(rec.activity_name, "Update");
        assert_eq!(rec.type_uid,      100103);
    }

    #[test]
    fn fim_deleted_is_delete() {
        let raw = r#"{
            "@timestamp":"2024-01-01T00:00:00Z",
            "agent":{"id":"1","name":"host","ip":""},
            "rule":{"id":"553","description":"FIM","level":7,"groups":["syscheck","syscheck_file"]},
            "decoder":{"name":"syscheck"},
            "syscheck":{"event":"deleted","path":"/etc/passwd"}
        }"#;
        let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(rec.activity_id,   4, "deleted → Delete(4)");
        assert_eq!(rec.activity_name, "Delete");
    }

    #[test]
    fn account_change_group_delete() {
        let raw = r#"{
            "@timestamp":"2024-01-01T00:00:00Z",
            "agent":{"id":"1","name":"host","ip":""},
            "rule":{"id":"1","description":"group deleted","level":3,
                    "groups":["adduser","groupdel"]},
            "decoder":{"name":"groupdel"}
        }"#;
        let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(rec.class_uid,     3001);
        assert_eq!(rec.activity_id,   8,  "groupdel → Delete Group(8), not Delete User(2)");
        assert_eq!(rec.activity_name, "Delete Group");
    }

    #[test]
    fn account_change_group_create() {
        let raw = r#"{
            "@timestamp":"2024-01-01T00:00:00Z",
            "agent":{"id":"1","name":"host","ip":""},
            "rule":{"id":"1","description":"group added","level":3,
                    "groups":["adduser","addgroup"]},
            "decoder":{"name":"addgroup"}
        }"#;
        let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(rec.activity_id,   7, "addgroup → Create Group(7)");
        assert_eq!(rec.activity_name, "Create Group");
    }

    // ── Literal dotted key lookup (first_str / first_port / first_u64) ───

    #[test]
    fn first_str_prefers_literal_key() {
        // Some decoder output stores "audit.exe" as a literal dotted JSON key
        // rather than nested {audit: {exe: ...}}.  first_str must find it.
        let flat = serde_json::json!({"audit.exe": "/bin/bash"});
        assert_eq!(first_str(&flat, &["audit.exe"]), "/bin/bash");
    }

    #[test]
    fn first_str_nested_fallback() {
        // Normal nested case: data.audit.exe is navigated by jpath
        let nested = serde_json::json!({"audit": {"exe": "/bin/bash"}});
        assert_eq!(first_str(&nested, &["audit.exe"]), "/bin/bash");
    }

    #[test]
    fn first_port_literal_key() {
        // Literal dotted key for port
        let flat = serde_json::json!({"audit.pid": "4321"});
        assert_eq!(first_port(&flat, &["audit.pid"]), 4321u16);
    }

    #[test]
    fn first_u64_literal_key() {
        // Literal dotted key for byte counter
        let flat = serde_json::json!({"rcvdbyte": "2048"});
        assert_eq!(first_u64(&flat, &["rcvdbyte"]), 2048u64);
    }
}
