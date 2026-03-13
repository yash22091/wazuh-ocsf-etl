//! Wazuh → OCSF → ClickHouse ETL pipeline
//!
//! ## Routing
//!
//! - `location` is in SPECIAL_LOCATIONS → table named after the **location**
//! - Otherwise → table named after the **agent.name**
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
//!   OCSF_VALIDATE         true (set to false to disable schema validation)

// ── Modules ───────────────────────────────────────────────────────────────────
mod classify;
mod config;
mod db;
mod field_paths;
mod json;
mod record;
mod state;
mod tailer;
mod transform;
mod unmapped;
mod validator;
mod zmq;

// ── Standard library ──────────────────────────────────────────────────────────
use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};

// ── External crates ──────────────────────────────────────────────────────────
use anyhow::Result;
use clickhouse::Client;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, error, info, trace, warn};

// ── Module imports ────────────────────────────────────────────────────────────
use config::{AppConfig, CustomMappings, InputMode, CONFIG_POLL_SECS};
use db::{flush_all, BatchMap};
use state::{StateStore, TailState};
use tailer::reader_task;
use transform::transform;
use unmapped::write_unmapped_report;
use validator::OCSF_VALIDATE;
use zmq::zmq_reader_task;

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn file_mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).ok().and_then(|m| m.modified().ok())
}

// ─── Config hot-reload watcher ────────────────────────────────────────────────

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

// ─── Flush helper ─────────────────────────────────────────────────────────────

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
    write_unmapped_report(&cfg.unmapped_fields_file);
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
                    tracing_subscriber::EnvFilter::new("info")
                }),
        )
        .with_target(false)
        .with_thread_ids(false)
        .init();

    let cfg = Arc::new(AppConfig::from_env());

    // ── OCSF validator: apply env var override ───────────────────────────
    {
        let enabled = std::env::var("OCSF_VALIDATE")
            .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no"))
            .unwrap_or(true);
        OCSF_VALIDATE.store(enabled, Ordering::Relaxed);
    }

    // ── Startup configuration sanity checks ──────────────────────────────
    if cfg.batch_size == 0 {
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

    // ── State: load saved byte offset + resolve effective start position ──
    let state_store = Arc::new(StateStore::new(cfg.state_file.clone()));
    let saved_state = state_store.load();

    let file_size: u64 = std::fs::metadata(&cfg.alerts_file)
        .map(|m| m.len()).unwrap_or(0);
    let current_inode: u64 = std::fs::metadata(&cfg.alerts_file)
        .map(|m| std::os::unix::fs::MetadataExt::ino(&m)).unwrap_or(0);

    let is_first_run = saved_state.offset == 0 && saved_state.inode == 0;

    let start_offset: u64 = if !is_first_run {
        if saved_state.inode != 0 && saved_state.inode != current_inode {
            saved_state.offset
        } else if saved_state.offset > file_size {
            warn!("State offset {} > file size {} — file was truncated. Starting from 0.",
                  saved_state.offset, file_size);
            0
        } else {
            saved_state.offset
        }
    } else if cfg.seek_to_end_on_first_run {
        file_size
    } else {
        0
    };

    let start_state = TailState { inode: current_inode, offset: start_offset };

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
    info!("  ocsf_validate    : {} (set OCSF_VALIDATE=false to disable)",
          OCSF_VALIDATE.load(Ordering::Relaxed));
    info!("  unmapped report  : {}", cfg.unmapped_fields_file.display());

    if cfg.unmapped_fields_file.exists() {
        if let Ok(txt) = std::fs::read_to_string(&cfg.unmapped_fields_file) {
            if let Ok(v) = serde_json::from_str::<Value>(&txt) {
                if let Some(fields) = v.get("fields").and_then(Value::as_object) {
                    let mut top: Vec<(u64, &str)> = fields.iter()
                        .filter_map(|(k, fv)| {
                            fv.get("count")
                                .and_then(Value::as_u64)
                                .map(|c| (c, k.as_str()))
                        })
                        .collect();
                    top.sort_by(|a, b| b.0.cmp(&a.0));
                    let shown: Vec<&str> = top.iter().take(10).map(|(_, k)| *k).collect();
                    if !shown.is_empty() {
                        info!("  top unmapped fields (add to field_mappings.toml): {:?}", shown);
                    }
                }
            }
        }
    }

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
    let (tx, mut rx) = mpsc::channel::<(u64, String)>(cfg.channel_cap);

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

    // ── Processing state ─────────────────────────────────────────────────
    let mut batches:      BatchMap        = HashMap::new();
    let mut known_tables: HashSet<String> = HashSet::new();
    let mut current_offset: u64 = start_state.offset;

    let mut flush_tick = interval(Duration::from_secs(cfg.flush_interval_secs));
    flush_tick.tick().await; // consume the immediate first tick

    // ── SIGTERM / SIGINT handlers ─────────────────────────────────────────
    let mut shutdown = std::pin::pin!(shutdown_signal());
    let mut shutting_down = false;

    // ── Main event loop ───────────────────────────────────────────────────
    loop {
        tokio::select! {
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
                                debug!(table = %table, rows = cfg.batch_size, "batch-size flush triggered");
                                do_flush(&client, &cfg, &mut batches, &mut known_tables,
                                         &state_store, current_offset).await;
                            }
                        }
                    }
                }
            }

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

            _ = &mut shutdown, if !shutting_down => {
                info!("Shutdown signal — draining channel and flushing…");
                shutting_down = true;
                rx.close();
            }
        }
    }

    info!("Shutdown complete. Committed offset={current_offset}");
    Ok(())
}

/// Resolves when SIGTERM **or** SIGINT is received — whichever comes first.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            error!("Ctrl-C signal handler error: {e:#} — graceful shutdown via Ctrl-C unavailable");
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
    use crate::classify::{classify_event, map_severity};
    use crate::config::CustomMappings;
    use crate::field_paths::{BYTES_IN, BYTES_OUT};
    use crate::json::{jpath, get_data_field, first_str, first_port, first_u64, flatten_to_paths};
    use crate::transform::{transform, routing_table};
    use crate::unmapped::{track_unmapped_fields, write_unmapped_report, UNMAPPED_TRACKER, FieldInfo};
    use std::collections::{HashMap, HashSet};
    use serde_json::Value;

    fn no_custom() -> CustomMappings { CustomMappings::default() }

    // ── Sanitise ─────────────────────────────────────────────────────────

    #[test]
    fn sanitize_path() {
        assert_eq!(crate::transform::sanitize_name("/var/log/auth.log"), "var_log_auth_log");
    }
    #[test]
    fn sanitize_dashes_dots() {
        assert_eq!(crate::transform::sanitize_name("agent-01.corp.local"), "agent_01_corp_local");
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
        let cases = [(0,"Unknown"),(1,"Informational"),(4,"Low"),
                     (7,"Medium"),(10,"High"),(13,"Critical"),(15,"Critical")];
        for (lvl, label) in cases { assert_eq!(map_severity(lvl).1, label, "level={lvl}"); }
    }
    #[test]
    fn severity_ids_are_valid_ocsf() {
        let valid: HashSet<u8> = [0,1,2,3,4,5,99].into();
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
        let v = serde_json::json!({"audit.command": "ls"});
        assert_eq!(get_data_field(&v, "audit.command"), "ls");
    }
    #[test]
    fn get_data_field_nested_fallback() {
        let v = serde_json::json!({"audit": {"command": "ls"}});
        assert_eq!(get_data_field(&v, "audit.command"), "ls");
    }
    #[test]
    fn get_data_field_number_and_bool() {
        let v = serde_json::json!({"port": 8443, "retries": 3, "tls": true});
        assert_eq!(get_data_field(&v, "port"),    "8443");
        assert_eq!(get_data_field(&v, "retries"), "3");
        assert_eq!(get_data_field(&v, "tls"),     "true");
    }
    #[test]
    fn get_data_field_nested_number() {
        let v = serde_json::json!({"conn": {"src_port": 12345}});
        assert_eq!(get_data_field(&v, "conn.src_port"), "12345");
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
        let (tbl, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(tbl, "db.ocsf_win_dc_01");
        assert_eq!(rec.src_ip,      "192.168.1.100");
        assert_eq!(rec.actor_user,  "Administrator");
        assert_eq!(rec.domain,      "CORP");
        assert_eq!(rec.src_hostname,"WIN-DC-01");
        assert_eq!(rec.status,      "0xC000006D");
        assert_eq!(rec.severity_id, 2);
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
        assert_eq!(tbl,             "db.ocsf_aws_cloudtrail");
        assert_eq!(rec.src_ip,      "52.1.2.3");
        assert_eq!(rec.actor_user,  "jdoe");
        assert_eq!(rec.domain,      "123456789");
        assert_eq!(rec.action,      "ConsoleLogin");
        assert_eq!(rec.status,      "Failed authentication");
    }

    // ── Auditd (literal dotted keys) ──────────────────────────────────────

    #[test]
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
        assert_eq!(rec.process_name, "/usr/bin/passwd");
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
    #[test]
    fn transform_custom_nat_and_network_fields() {
        let raw = r#"{
            "agent":{"id":"009","name":"nathost","ip":""},
            "rule": {"id":"1","description":"t","level":3},
            "data": {
                "vendor.nat_src":  "10.1.1.1",
                "vendor.nat_dst":  "10.2.2.2",
                "vendor.nsp":      "40000",
                "vendor.ndp":      "443",
                "vendor.iface_in": "eth0",
                "vendor.iface_out":"eth1",
                "vendor.bytes_in": "1024",
                "vendor.bytes_out":"2048",
                "vendor.proto":    "udp",
                "vendor.dst_host": "internal.corp"
            }
        }"#;
        let mut cm = no_custom();
        cm.field_map.insert("vendor.nat_src".into(),  "nat_src_ip".into());
        cm.field_map.insert("vendor.nat_dst".into(),  "nat_dst_ip".into());
        cm.field_map.insert("vendor.nsp".into(),      "nat_src_port".into());
        cm.field_map.insert("vendor.ndp".into(),      "nat_dst_port".into());
        cm.field_map.insert("vendor.iface_in".into(), "interface_in".into());
        cm.field_map.insert("vendor.iface_out".into(),"interface_out".into());
        cm.field_map.insert("vendor.bytes_in".into(), "bytes_in".into());
        cm.field_map.insert("vendor.bytes_out".into(),"bytes_out".into());
        cm.field_map.insert("vendor.proto".into(),    "network_protocol".into());
        cm.field_map.insert("vendor.dst_host".into(), "dst_hostname".into());
        let (_, rec) = transform(raw, "db", &[], &cm).unwrap();
        assert_eq!(rec.nat_src_ip,       "10.1.1.1",       "nat_src_ip");
        assert_eq!(rec.nat_dst_ip,       "10.2.2.2",       "nat_dst_ip");
        assert_eq!(rec.nat_src_port,     40000u16,          "nat_src_port");
        assert_eq!(rec.nat_dst_port,     443u16,            "nat_dst_port");
        assert_eq!(rec.interface_in,     "eth0",            "interface_in");
        assert_eq!(rec.interface_out,    "eth1",            "interface_out");
        assert_eq!(rec.bytes_in,         1024u64,           "bytes_in");
        assert_eq!(rec.bytes_out,        2048u64,           "bytes_out");
        assert_eq!(rec.network_protocol, "udp",             "network_protocol");
        assert_eq!(rec.dst_hostname,     "internal.corp",   "dst_hostname");
        let ext: Value = serde_json::from_str(&rec.extensions).unwrap();
        assert!(ext.as_object().unwrap().is_empty(), "extensions should be empty");
    }
    #[test]
    fn transform_custom_nat_wont_override_existing() {
        let raw = r#"{
            "agent":{"id":"010","name":"nathost2","ip":""},
            "rule": {"id":"1","description":"t","level":3},
            "data": {
                "protocol": "tcp",
                "vendor.proto": "udp"
            }
        }"#;
        let mut cm = no_custom();
        cm.field_map.insert("vendor.proto".into(), "network_protocol".into());
        let (_, rec) = transform(raw, "db", &[], &cm).unwrap();
        assert_eq!(rec.network_protocol, "tcp", "built-in should win, not custom");
    }
    #[test]
    fn transform_json_decoder_numeric_fields() {
        let raw = r#"{
            "agent":  {"id":"020","name":"myapp-json","ip":"10.0.0.20"},
            "rule":   {"id":"5001","description":"myapp event","level":4},
            "decoder":{"name":"json"},
            "data": {
                "client_ip":   "172.16.0.5",
                "server_ip":   "10.0.1.1",
                "client_port": 54321,
                "server_port": 443,
                "bytes_recv":  10240,
                "bytes_sent":  2048,
                "username":    "alice",
                "risk":        99
            }
        }"#;
        let mut cm = no_custom();
        cm.field_map.insert("client_ip".into(),   "src_ip".into());
        cm.field_map.insert("server_ip".into(),   "dst_ip".into());
        cm.field_map.insert("client_port".into(), "src_port".into());
        cm.field_map.insert("server_port".into(), "dst_port".into());
        cm.field_map.insert("bytes_recv".into(),  "bytes_in".into());
        cm.field_map.insert("bytes_sent".into(),  "bytes_out".into());
        cm.field_map.insert("username".into(),    "actor_user".into());
        cm.field_map.insert("risk".into(),        "risk_score".into());
        let (_, rec) = transform(raw, "db", &[], &cm).unwrap();
        assert_eq!(rec.src_ip,    "172.16.0.5", "src_ip from JSON number decoder");
        assert_eq!(rec.dst_ip,    "10.0.1.1",   "dst_ip");
        assert_eq!(rec.src_port,  54321u16,      "src_port from JSON number");
        assert_eq!(rec.dst_port,  443u16,        "dst_port from JSON number");
        assert_eq!(rec.bytes_in,  10240u64,      "bytes_in from JSON number");
        assert_eq!(rec.bytes_out, 2048u64,       "bytes_out from JSON number");
        assert_eq!(rec.actor_user,"alice",        "actor_user");
        let ext: Value = serde_json::from_str(&rec.extensions).unwrap();
        assert_eq!(ext["risk_score"].as_str(), Some("99"), "numeric → extensions");
    }
    #[test]
    fn transform_json_decoder_nested_object() {
        let raw = r#"{
            "agent":  {"id":"021","name":"myapp-nested","ip":""},
            "rule":   {"id":"5002","description":"nested test","level":3},
            "decoder":{"name":"json"},
            "data": {
                "connection": {
                    "src":  "192.0.2.10",
                    "dst":  "198.51.100.1",
                    "port": 8443
                },
                "auth": {
                    "user":   "bob",
                    "domain": "CORP"
                },
                "threat": {
                    "score": 75,
                    "name":  "BruteForce"
                }
            }
        }"#;
        let mut cm = no_custom();
        cm.field_map.insert("connection.src".into(),   "src_ip".into());
        cm.field_map.insert("connection.dst".into(),   "dst_ip".into());
        cm.field_map.insert("connection.port".into(),  "dst_port".into());
        cm.field_map.insert("auth.user".into(),        "actor_user".into());
        cm.field_map.insert("auth.domain".into(),      "domain".into());
        cm.field_map.insert("threat.score".into(),     "threat_score".into());
        cm.field_map.insert("threat.name".into(),      "rule_name".into());
        let (_, rec) = transform(raw, "db", &[], &cm).unwrap();
        assert_eq!(rec.src_ip,    "192.0.2.10",   "nested src_ip");
        assert_eq!(rec.dst_ip,    "198.51.100.1", "nested dst_ip");
        assert_eq!(rec.dst_port,  8443u16,         "nested numeric port");
        assert_eq!(rec.actor_user,"bob",            "nested actor_user");
        assert_eq!(rec.domain,    "CORP",           "nested domain");
        assert_eq!(rec.rule_name, "BruteForce",     "nested rule_name");
        let ext: Value = serde_json::from_str(&rec.extensions).unwrap();
        assert_eq!(ext["threat_score"].as_str(), Some("75"), "nested number → extensions");
    }
    #[test]
    fn custom_mappings_full_toml_roundtrip() {
        let toml_content = r#"
[meta]
ocsf_version = "1.7.0"

[field_mappings]
"myapp.client_addr"  = "src_ip"
"myapp.server_addr"  = "dst_ip"
"myapp.current_user" = "actor_user"
"myapp.risk_score"   = "vendor_risk_score"
"myapp.proto"        = "network_protocol"
"myapp.nat_ip"       = "nat_src_ip"
"myapp.iface"        = "interface_in"
"myapp.brecv"        = "bytes_in"
"myapp.bsent"        = "bytes_out"
"myapp.dst_h"        = "dst_hostname"
"#;
        let tmp = std::env::temp_dir().join("test_field_mappings_roundtrip.toml");
        std::fs::write(&tmp, toml_content).unwrap();
        let cm = CustomMappings::load(&tmp).expect("TOML must parse");

        assert_eq!(cm.ocsf_version, "1.7.0");
        assert_eq!(cm.field_map.get("myapp.client_addr").map(String::as_str),  Some("src_ip"));
        assert_eq!(cm.field_map.get("myapp.server_addr").map(String::as_str),  Some("dst_ip"));
        assert_eq!(cm.field_map.get("myapp.current_user").map(String::as_str), Some("actor_user"));
        assert_eq!(cm.field_map.get("myapp.risk_score").map(String::as_str),   Some("vendor_risk_score"));

        let raw = r#"{
            "agent":{"id":"011","name":"myapp-server","ip":"10.0.0.1"},
            "rule": {"id":"100","description":"myapp event","level":5},
            "data": {
                "myapp.client_addr":  "192.168.1.50",
                "myapp.server_addr":  "10.0.0.5",
                "myapp.current_user": "alice",
                "myapp.risk_score":   "87",
                "myapp.proto":        "udp",
                "myapp.nat_ip":       "203.0.113.1",
                "myapp.iface":        "eth0",
                "myapp.brecv":        "1024",
                "myapp.bsent":        "2048",
                "myapp.dst_h":        "backend.corp"
            }
        }"#;
        let (_, rec) = transform(raw, "db", &[], &cm).unwrap();
        assert_eq!(rec.src_ip,           "192.168.1.50",  "src_ip");
        assert_eq!(rec.dst_ip,           "10.0.0.5",      "dst_ip");
        assert_eq!(rec.actor_user,       "alice",          "actor_user");
        assert_eq!(rec.network_protocol, "udp",            "network_protocol");
        assert_eq!(rec.nat_src_ip,       "203.0.113.1",   "nat_src_ip");
        assert_eq!(rec.interface_in,     "eth0",           "interface_in");
        assert_eq!(rec.bytes_in,         1024u64,          "bytes_in");
        assert_eq!(rec.bytes_out,        2048u64,          "bytes_out");
        assert_eq!(rec.dst_hostname,     "backend.corp",   "dst_hostname");
        let ext: Value = serde_json::from_str(&rec.extensions).unwrap();
        assert_eq!(ext["vendor_risk_score"].as_str(), Some("87"), "extension");

        std::fs::remove_file(&tmp).ok();
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
        let u: Value = serde_json::from_str(&rec.unmapped).unwrap();
        assert!(u.get("custom_toplevel").is_some(), "missing custom_toplevel");
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

    // ── cloud source routing ─────────────────────────────────────────────

    #[test]
    fn classify_vpcflow_decoder_is_network_activity() {
        let c = classify_event(&[], "aws-vpcflow", "");
        assert_eq!(c.class_uid, 4001);
        assert_eq!(c.class_name, "Network Activity");
    }
    #[test]
    fn classify_vpcflow_hyphen_variant() {
        let c = classify_event(&[], "vpc-flow-logs", "");
        assert_eq!(c.class_uid, 4001);
    }
    #[test]
    fn classify_guardduty_decoder_is_vulnerability_finding() {
        let c = classify_event(&[], "aws-guardduty", "");
        assert_eq!(c.class_uid, 2002);
        assert_eq!(c.class_name, "Vulnerability Finding");
    }
    #[test]
    fn classify_guardduty_group_is_vulnerability_finding() {
        let c = classify_event(&["amazon-guardduty"], "json", "");
        assert_eq!(c.class_uid, 2002);
    }
    #[test]
    fn classify_okta_decoder_is_authentication() {
        let c = classify_event(&[], "okta", "");
        assert_eq!(c.class_uid, 3002);
        assert_eq!(c.class_name, "Authentication");
    }
    #[test]
    fn classify_okta_group_is_authentication() {
        let c = classify_event(&["okta"], "json", "");
        assert_eq!(c.class_uid, 3002);
    }
    #[test]
    fn classify_azure_ad_decoder_is_authentication() {
        let c = classify_event(&[], "azure-ad", "");
        assert_eq!(c.class_uid, 3002);
        assert_eq!(c.class_name, "Authentication");
    }
    #[test]
    fn classify_azure_ad_underscore_is_authentication() {
        let c = classify_event(&[], "azure_ad", "");
        assert_eq!(c.class_uid, 3002);
    }
    #[test]
    fn classify_zeek_decoder_is_network_activity() {
        let c = classify_event(&[], "zeek", "");
        assert_eq!(c.class_uid, 4001);
        assert_eq!(c.class_name, "Network Activity");
    }
    #[test]
    fn classify_bro_group_is_network_activity() {
        let c = classify_event(&["bro"], "bro-ids", "");
        assert_eq!(c.class_uid, 4001);
    }
    #[test]
    fn classify_cloudtrail_iam_is_authentication() {
        let c = classify_event(&["aws_iam"], "aws-cloudtrail", "");
        assert_eq!(c.class_uid, 3002);
        assert_eq!(c.class_name, "Authentication");
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

    #[test]
    fn type_uid_is_class_times_100_plus_activity() {
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

    // ── Literal dotted key lookup ─────────────────────────────────────────

    #[test]
    fn first_str_prefers_literal_key() {
        let flat = serde_json::json!({"audit.exe": "/bin/bash"});
        assert_eq!(first_str(&flat, &["audit.exe"]), "/bin/bash");
    }
    #[test]
    fn first_str_nested_fallback() {
        let nested = serde_json::json!({"audit": {"exe": "/bin/bash"}});
        assert_eq!(first_str(&nested, &["audit.exe"]), "/bin/bash");
    }
    #[test]
    fn first_port_literal_key() {
        let flat = serde_json::json!({"audit.pid": "4321"});
        assert_eq!(first_port(&flat, &["audit.pid"]), 4321u16);
    }
    #[test]
    fn first_u64_literal_key() {
        let flat = serde_json::json!({"rcvdbyte": "2048"});
        assert_eq!(first_u64(&flat, &["rcvdbyte"]), 2048u64);
    }

    // ── flatten_to_paths tests ────────────────────────────────────────────

    #[test]
    fn flatten_flat_object() {
        let v = serde_json::json!({"a": "1", "b": "2"});
        let mut out = vec![];
        flatten_to_paths(&v, "", &mut out);
        out.sort();
        assert_eq!(out, vec![("a".into(), "1".into()), ("b".into(), "2".into())]);
    }
    #[test]
    fn flatten_nested_object() {
        let v = serde_json::json!({"a": {"b": {"c": "deep"}}});
        let mut out = vec![];
        flatten_to_paths(&v, "", &mut out);
        assert_eq!(out, vec![("a.b.c".into(), "deep".into())]);
    }
    #[test]
    fn flatten_numeric_leaf() {
        let v = serde_json::json!({"port": 443});
        let mut out = vec![];
        flatten_to_paths(&v, "", &mut out);
        assert_eq!(out, vec![("port".into(), "443".into())]);
    }
    #[test]
    fn flatten_bool_leaf() {
        let v = serde_json::json!({"enabled": true});
        let mut out = vec![];
        flatten_to_paths(&v, "", &mut out);
        assert_eq!(out, vec![("enabled".into(), "true".into())]);
    }
    #[test]
    fn flatten_skips_null() {
        let v = serde_json::json!({"a": null, "b": "ok"});
        let mut out = vec![];
        flatten_to_paths(&v, "", &mut out);
        assert_eq!(out, vec![("b".into(), "ok".into())]);
    }

    // ── track_unmapped_fields tests ───────────────────────────────────────

    #[test]
    fn unmapped_known_path_not_recorded() {
        let snapshot_before: HashMap<String, FieldInfo> = {
            let g = UNMAPPED_TRACKER.lock().unwrap();
            g.clone()
        };
        let data = serde_json::json!({"srcip": "1.2.3.4"});
        track_unmapped_fields(&data, &no_custom());
        let snapshot_after: HashMap<String, FieldInfo> = {
            let g = UNMAPPED_TRACKER.lock().unwrap();
            g.clone()
        };
        let new_keys: HashSet<&String> = snapshot_after.keys()
            .filter(|k| !snapshot_before.contains_key(*k))
            .collect();
        assert!(!new_keys.contains(&"srcip".to_string()),
                "srcip is a KNOWN_PATH and must not be recorded as unmapped");
    }
    #[test]
    fn unmapped_unknown_path_is_recorded() {
        let before_count = UNMAPPED_TRACKER.lock().unwrap()
            .get("my_custom_widget").map(|f| f.count).unwrap_or(0);
        let data = serde_json::json!({"my_custom_widget": "xyz"});
        track_unmapped_fields(&data, &no_custom());
        let after_count = UNMAPPED_TRACKER.lock().unwrap()
            .get("my_custom_widget").map(|f| f.count).unwrap_or(0);
        assert_eq!(after_count, before_count + 1,
            "unknown field must be recorded in UNMAPPED_TRACKER");
    }
    #[test]
    fn unmapped_custom_mapped_field_not_recorded() {
        let field = "my_mapped_field_xyz";
        let mut cm = no_custom();
        cm.field_map.insert(field.to_string(), "src_ip".to_string());
        let before = UNMAPPED_TRACKER.lock().unwrap()
            .get(field).map(|f| f.count).unwrap_or(0);
        let data = serde_json::json!({"my_mapped_field_xyz": "10.0.0.1"});
        track_unmapped_fields(&data, &cm);
        let after = UNMAPPED_TRACKER.lock().unwrap()
            .get(field).map(|f| f.count).unwrap_or(0);
        assert_eq!(after, before, "custom-mapped field must not appear in unmapped tracker");
    }
    #[test]
    fn unmapped_nested_unknown_path_is_recorded() {
        let key = "vendor.info.extra_field_abc123";
        let before = UNMAPPED_TRACKER.lock().unwrap()
            .get(key).map(|f| f.count).unwrap_or(0);
        let data = serde_json::json!({"vendor": {"info": {"extra_field_abc123": "v"}}});
        track_unmapped_fields(&data, &no_custom());
        let after = UNMAPPED_TRACKER.lock().unwrap()
            .get(key).map(|f| f.count).unwrap_or(0);
        assert_eq!(after, before + 1);
    }
    #[test]
    fn write_unmapped_report_creates_valid_json() {
        {
            let mut g = UNMAPPED_TRACKER.lock().unwrap();
            g.insert("test_write_field".to_string(), FieldInfo {
                count: 7,
                example: "hello".to_string(),
                suggested_toml: "# test".to_string(),
            });
        }
        let tmp = std::env::temp_dir().join("wazuh_ocsf_unmapped_test.json");
        write_unmapped_report(&tmp);
        let txt = std::fs::read_to_string(&tmp).expect("report file must exist");
        let v: Value = serde_json::from_str(&txt).expect("must be valid JSON");
        assert!(v.get("fields").is_some(), "must have 'fields' key");
        assert!(v["fields"].get("test_write_field").is_some(),
                "test_write_field must appear in report");
        assert_eq!(v["fields"]["test_write_field"]["count"], 7);
        let _ = std::fs::remove_file(&tmp);
    }

    // ── Cloud / JSON-decoder source integration tests ────────────────────

    #[test]
    fn transform_vpcflow_fields() {
        let raw = r#"{
            "@timestamp":"2024-05-01T10:00:00Z",
            "agent":{"id":"010","name":"aws-agent","ip":""},
            "rule":{"id":"87001","description":"VPC Flow","level":3,"groups":["amazon-vpcflow"]},
            "manager":{"name":"mgr"},
            "decoder":{"name":"aws-vpcflow"},
            "location":"aws-vpcflow",
            "data":{
                "srcAddr":"10.1.2.3",
                "dstAddr":"10.4.5.6",
                "srcPort":54321,
                "dstPort":443,
                "protocol":"6",
                "bytes":2048,
                "packets":12,
                "interfaceId":"eni-abc123",
                "action":"ACCEPT"
            }
        }"#;
        let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(rec.class_uid, 4001, "VPC Flow must be Network Activity");
        assert_eq!(rec.src_ip,   "10.1.2.3");
        assert_eq!(rec.dst_ip,   "10.4.5.6");
        assert_eq!(rec.src_port, 54321u16);
        assert_eq!(rec.dst_port, 443u16);
        assert_eq!(rec.bytes_in, 2048u64);
        assert_eq!(rec.action,   "ACCEPT");
    }
    #[test]
    fn transform_guardduty_nested_ip() {
        let raw = r#"{
            "@timestamp":"2024-05-02T11:00:00Z",
            "agent":{"id":"011","name":"aws-agent","ip":""},
            "rule":{"id":"87100","description":"GuardDuty","level":10,"groups":["amazon-guardduty"]},
            "manager":{"name":"mgr"},
            "decoder":{"name":"aws-guardduty"},
            "location":"aws-guardduty",
            "data":{
                "aws":{
                    "service":{
                        "action":{
                            "networkConnectionAction":{
                                "remoteIpDetails":{"ipAddressV4":"198.51.100.7"},
                                "remotePortDetails":{"port":4444},
                                "localIpDetails":{"ipAddressV4":"172.16.0.5"},
                                "localPortDetails":{"port":443}
                            }
                        }
                    },
                    "title":"UnauthorizedAccess:EC2/SSHBruteForce"
                }
            }
        }"#;
        let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(rec.class_uid, 2002, "GuardDuty must be Vulnerability Finding");
        assert_eq!(rec.src_ip,   "198.51.100.7");
        assert_eq!(rec.dst_ip,   "172.16.0.5");
        assert_eq!(rec.src_port, 4444u16);
        assert_eq!(rec.dst_port, 443u16);
    }
    #[test]
    fn transform_okta_auth_event() {
        let raw = r#"{
            "@timestamp":"2024-05-03T09:00:00Z",
            "agent":{"id":"012","name":"okta-agent","ip":""},
            "rule":{"id":"92000","description":"Okta login","level":5,"groups":["okta"]},
            "manager":{"name":"mgr"},
            "decoder":{"name":"okta"},
            "location":"okta",
            "data":{
                "okta":{
                    "actor":{
                        "alternateId":"alice@example.com",
                        "displayName":"Alice"
                    },
                    "client":{"ipAddress":"203.0.113.42"},
                    "outcome":{"result":"SUCCESS"},
                    "displayMessage":"User login to Okta",
                    "eventType":"user.session.start"
                }
            }
        }"#;
        let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(rec.class_uid,   3002, "Okta must be Authentication");
        assert_eq!(rec.src_ip,      "203.0.113.42");
        assert_eq!(rec.actor_user,  "alice@example.com");
        assert_eq!(rec.status,      "SUCCESS");
        assert_eq!(rec.action,      "User login to Okta");
    }
    #[test]
    fn transform_azure_ad_signin() {
        let raw = r#"{
            "@timestamp":"2024-05-04T08:00:00Z",
            "agent":{"id":"013","name":"azure-agent","ip":""},
            "rule":{"id":"93000","description":"Azure AD","level":5,"groups":["azure-ad"]},
            "manager":{"name":"mgr"},
            "decoder":{"name":"azure-ad"},
            "location":"azure-ad",
            "data":{
                "azure":{
                    "callerIpAddress":"203.0.113.99",
                    "operationName":"Sign-in activity",
                    "resultType":"0",
                    "properties":{
                        "userPrincipalName":"bob@corp.onmicrosoft.com"
                    }
                }
            }
        }"#;
        let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(rec.class_uid,  3002, "Azure AD must be Authentication");
        assert_eq!(rec.src_ip,     "203.0.113.99");
        assert_eq!(rec.actor_user, "bob@corp.onmicrosoft.com");
        assert_eq!(rec.action,     "Sign-in activity");
        assert_eq!(rec.status,     "0");
    }
    #[test]
    fn transform_zeek_conn_log() {
        let raw = r#"{
            "@timestamp":"2024-05-05T07:00:00Z",
            "agent":{"id":"014","name":"zeek-node","ip":""},
            "rule":{"id":"94000","description":"Zeek conn","level":3,"groups":["zeek"]},
            "manager":{"name":"mgr"},
            "decoder":{"name":"zeek"},
            "location":"zeek",
            "data":{
                "zeek":{
                    "_path":"conn",
                    "id":{
                        "orig_h":"192.168.1.10",
                        "orig_p":52000,
                        "resp_h":"93.184.216.34",
                        "resp_p":80
                    }
                }
            }
        }"#;
        let (_, rec) = transform(raw, "db", &[], &no_custom()).unwrap();
        assert_eq!(rec.class_uid, 4001, "Zeek conn must be Network Activity");
        assert_eq!(rec.src_ip,   "192.168.1.10");
        assert_eq!(rec.dst_ip,   "93.184.216.34");
        assert_eq!(rec.src_port, 52000u16);
        assert_eq!(rec.dst_port, 80u16);
    }
}
