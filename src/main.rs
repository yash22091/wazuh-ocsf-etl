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
mod config;
mod input;
mod output;
mod pipeline;
mod util;

// ── Standard library ──────────────────────────────────────────────────────────
use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
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
use input::state::{StateStore, TailState};
use input::tailer::reader_task;
use input::zmq::zmq_reader_task;
use output::db::{ensure_custom_columns, flush_all, BatchMap};
use pipeline::transform::transform;
use pipeline::validator::OCSF_VALIDATE;
use util::unmapped::{archive_unmapped_report, write_unmapped_report};

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn file_mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).ok().and_then(|m| m.modified().ok())
}

// ─── Config hot-reload watcher ────────────────────────────────────────────────

async fn config_watcher_task(path: PathBuf, mappings: Arc<RwLock<CustomMappings>>) {
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
                        Ok(g) => g,
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
    client: &Client,
    cfg: &AppConfig,
    batches: &mut BatchMap,
    known_tables: &mut HashSet<String>,
    known_custom_cols: &mut HashSet<String>,
    custom_mappings: &std::sync::RwLock<config::CustomMappings>,
    store: &StateStore,
    offset: u64,
) {
    // Detect new custom column targets added since last flush (hot-reload)
    let new_cols: Vec<String> = {
        let g = match custom_mappings.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        g.custom_column_targets()
            .into_iter()
            .filter(|c| !known_custom_cols.contains(c))
            .collect()
    };
    if !new_cols.is_empty() {
        // Apply new columns to all already-known tables.
        // A column is only marked as "registered" when every existing table
        // accepted it — so a transient DDL failure causes a retry on the next
        // flush (IF NOT EXISTS makes each attempt idempotent / safe to retry).
        let mut failed: std::collections::HashSet<String> = std::collections::HashSet::new();
        for table in known_tables.iter() {
            let applied = ensure_custom_columns(
                &cfg.clickhouse_url,
                &cfg.clickhouse_user,
                &cfg.clickhouse_password,
                table,
                &new_cols,
            )
            .await;
            let applied_set: std::collections::HashSet<_> = applied.into_iter().collect();
            for col in &new_cols {
                if !applied_set.contains(col) {
                    failed.insert(col.clone());
                }
            }
        }
        for col in &new_cols {
            if !failed.contains(col) {
                info!("hot-reload: custom column registered: `{col}`");
                known_custom_cols.insert(col.clone());
            } else {
                warn!("custom column `{col}` failed for some tables — will retry next flush");
            }
        }
    }
    let all_custom: Vec<String> = known_custom_cols.iter().cloned().collect();
    flush_all(
        client,
        &cfg.clickhouse_url,
        &cfg.clickhouse_user,
        &cfg.clickhouse_password,
        &cfg.clickhouse_db,
        cfg.data_ttl_days,
        batches,
        known_tables,
        &all_custom,
    )
    .await;
    let inode = std::fs::metadata(&cfg.alerts_file)
        .map(|m| m.ino())
        .unwrap_or(0);
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
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
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
        warn!(
            "BATCH_SIZE=0 — every row will be flushed individually (very slow). \
               Set BATCH_SIZE to at least 100."
        );
    }
    if cfg.flush_interval_secs == 0 {
        warn!(
            "FLUSH_INTERVAL_SECS=0 — the timer will fire as fast as the tokio \
               scheduler allows. Set to at least 1."
        );
    }
    if cfg.channel_cap < cfg.batch_size * 2 {
        warn!(
            "CHANNEL_CAP ({}) < BATCH_SIZE ({}) × 2 — the reader will be forced to pause \
             during every ClickHouse flush. Recommended minimum: {}",
            cfg.channel_cap,
            cfg.batch_size,
            cfg.batch_size * 10
        );
    }

    // ── State: load saved byte offset + resolve effective start position ──
    let state_store = Arc::new(StateStore::new(cfg.state_file.clone()));
    let saved_state = state_store.load();

    let file_size: u64 = std::fs::metadata(&cfg.alerts_file)
        .map(|m| m.len())
        .unwrap_or(0);
    let current_inode: u64 = std::fs::metadata(&cfg.alerts_file)
        .map(|m| std::os::unix::fs::MetadataExt::ino(&m))
        .unwrap_or(0);

    let is_first_run = saved_state.offset == 0 && saved_state.inode == 0;

    let start_offset: u64 = if !is_first_run {
        if saved_state.inode != 0 && saved_state.inode != current_inode {
            saved_state.offset
        } else if saved_state.offset > file_size {
            warn!(
                "State offset {} > file size {} — file was truncated. Starting from 0.",
                saved_state.offset, file_size
            );
            0
        } else {
            saved_state.offset
        }
    } else if cfg.seek_to_end_on_first_run {
        file_size
    } else {
        0
    };

    let start_state = TailState {
        inode: current_inode,
        offset: start_offset,
    };

    if is_first_run && start_offset > 0 {
        let _ = state_store.save(&start_state);
    }

    // ── Custom field mappings (non-fatal if absent) ────────────────────────
    let initial_mappings = CustomMappings::load(&cfg.mappings_file).unwrap_or_else(|e| {
        warn!("field_mappings.toml not loaded ({e:#}), using defaults");
        CustomMappings::default()
    });

    info!("=== Wazuh → OCSF → ClickHouse ETL ===");
    info!(
        "  alerts_file      : {} (size: {:.1} MB)",
        cfg.alerts_file,
        file_size as f64 / 1_048_576.0
    );
    info!(
        "  start_offset     : {}  ({:.1} MB to process on startup)",
        start_offset,
        (file_size.saturating_sub(start_offset)) as f64 / 1_048_576.0
    );
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
            info!(
                "  catch_up         : {:.1} MB written while service was stopped",
                gap as f64 / 1_048_576.0
            );
        }
    }
    info!("  state_file       : {}", cfg.state_file.display());
    info!("  seek_end_on_first : {}", cfg.seek_to_end_on_first_run);
    info!(
        "  input_mode       : {}",
        match cfg.input_mode {
            InputMode::File => format!("FILE  ({})", cfg.alerts_file),
            InputMode::ZeroMq => format!("ZEROMQ  ({})", cfg.zeromq_uri),
        }
    );
    info!(
        "  batch_size       : {}   flush: every {}s   channel_cap: {} (~{} MB max in-flight)",
        cfg.batch_size,
        cfg.flush_interval_secs,
        cfg.channel_cap,
        cfg.channel_cap / 1024
    );
    info!("  special_locations: {:?}", cfg.special_locations);
    info!("  data_ttl_days    : {:?}", cfg.data_ttl_days);
    info!("  ocsf_version     : {}", initial_mappings.ocsf_version);
    info!(
        "  custom_mappings  : {} rule(s)",
        initial_mappings.field_map.len()
    );
    info!(
        "  ocsf_validate    : {} (set OCSF_VALIDATE=false to disable)",
        OCSF_VALIDATE.load(Ordering::Relaxed)
    );
    info!(
        "  unmapped report  : {}",
        cfg.unmapped_fields_file.display()
    );

    // Archive the previous session's report before this session begins accumulating.
    // This ensures that data discovered before the restart is never silently lost.
    archive_unmapped_report(&cfg.unmapped_fields_file);

    if cfg.unmapped_fields_file.exists() {
        if let Ok(txt) = std::fs::read_to_string(&cfg.unmapped_fields_file) {
            if let Ok(v) = serde_json::from_str::<Value>(&txt) {
                if let Some(fields) = v.get("fields").and_then(Value::as_array) {
                    let shown: Vec<&str> =
                        fields.iter().filter_map(Value::as_str).take(10).collect();
                    if !shown.is_empty() {
                        info!(
                            "  top unmapped fields (add to field_mappings.toml): {:?}",
                            shown
                        );
                    }
                }
            }
        }
    }

    for (old, new_col) in &initial_mappings.ocsf_renames {
        warn!(
            "OCSF rename pending: `{old}` → `{new_col}`. \
               Run: ALTER TABLE <db>.<table> RENAME COLUMN `{old}` TO `{new_col}`;"
        );
    }

    let custom_mappings: Arc<RwLock<CustomMappings>> = Arc::new(RwLock::new(initial_mappings));

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
    let mut batches: BatchMap = HashMap::new();
    let mut known_tables: HashSet<String> = HashSet::new();
    // Tracks custom ClickHouse columns already applied via ALTER TABLE so we
    // only issue DDL once per new unique target across all hot-reloads.
    let mut known_custom_cols: HashSet<String> = HashSet::new();
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
                                 &mut known_custom_cols, &custom_mappings,
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
                                .map(|(tbl, mut rec)| {
                                    if !cfg.store_raw_data { rec.raw_data = String::new(); }
                                    (tbl, rec)
                                })
                        };
                        if let Some((table, record)) = record_opt {
                            let bucket = batches.entry(table.clone()).or_default();
                            bucket.push(record);
                            if bucket.len() >= cfg.batch_size {
                                debug!(table = %table, rows = cfg.batch_size, "batch-size flush triggered");
                                do_flush(&client, &cfg, &mut batches, &mut known_tables,
                                         &mut known_custom_cols, &custom_mappings,
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
                             &mut known_custom_cols, &custom_mappings,
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
            Ok(mut sig) => {
                sig.recv().await;
            }
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

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
