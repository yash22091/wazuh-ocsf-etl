use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use clickhouse::Client;
use tracing::{debug, error, info, trace};

use crate::record::OcsfRecord;

// ─── Batch / flush ────────────────────────────────────────────────────────────

pub(crate) type BatchMap = HashMap<String, Vec<OcsfRecord>>;

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

pub(crate) async fn flush_all(
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

// ─── ClickHouse DDL ───────────────────────────────────────────────────────────

pub(crate) async fn ensure_table(
    _client:  &Client,
    url:      &str,
    user:     &str,
    password: &str,
    db:       &str,
    table:    &str,
    ttl_days: Option<u32>,
) -> Result<()> {
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

    let (db_part, tbl_part) = table.split_once('.').unwrap_or((db, table));

    let ddl = format!(r#"CREATE TABLE IF NOT EXISTS `{db_part}`.`{tbl_part}` (
    `time`              DateTime                        CODEC(Delta(4), ZSTD(1)),
    `time_dt`           String                          CODEC(ZSTD(3)),
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
    `device_uid`        String                          CODEC(ZSTD(3)),
    `device_name`       LowCardinality(String)          CODEC(ZSTD(1)),
    `device_ip`         String                          CODEC(ZSTD(3)),
    `src_ip`            String                          CODEC(ZSTD(3)),
    `dst_ip`            String                          CODEC(ZSTD(3)),
    `src_port`          UInt16                          CODEC(Delta(2), ZSTD(1)),
    `dst_port`          UInt16                          CODEC(Delta(2), ZSTD(1)),
    `nat_src_ip`        String                          CODEC(ZSTD(3)),
    `nat_dst_ip`        String                          CODEC(ZSTD(3)),
    `nat_src_port`      UInt16                          CODEC(Delta(2), ZSTD(1)),
    `nat_dst_port`      UInt16                          CODEC(Delta(2), ZSTD(1)),
    `network_protocol`  LowCardinality(String)          CODEC(ZSTD(1)),
    `bytes_in`          UInt64                          CODEC(Delta(8), ZSTD(1)),
    `bytes_out`         UInt64                          CODEC(Delta(8), ZSTD(1)),
    `actor_user`        String                          CODEC(ZSTD(3)),
    `target_user`       String                          CODEC(ZSTD(3)),
    `domain`            String                          CODEC(ZSTD(3)),
    `url`               String                          CODEC(ZSTD(3)),
    `http_method`       LowCardinality(String)          CODEC(ZSTD(1)),
    `http_status`       UInt16                          CODEC(Delta(2), ZSTD(1)),
    `app_name`          LowCardinality(String)          CODEC(ZSTD(1)),
    `src_hostname`      String                          CODEC(ZSTD(3)),
    `dst_hostname`      String                          CODEC(ZSTD(3)),
    `file_name`         String                          CODEC(ZSTD(3)),
    `process_name`      String                          CODEC(ZSTD(3)),
    `process_id`        UInt32                          CODEC(Delta(4), ZSTD(1)),
    `interface_in`      LowCardinality(String)          CODEC(ZSTD(1)),
    `interface_out`     LowCardinality(String)          CODEC(ZSTD(1)),
    `rule_name`         String                          CODEC(ZSTD(3)),
    `app_category`      LowCardinality(String)          CODEC(ZSTD(1)),
    `finding_title`     String                          CODEC(ZSTD(3)),
    `finding_uid`       LowCardinality(String)          CODEC(ZSTD(1)),
    `finding_types`     String                          CODEC(ZSTD(3)),
    `wazuh_rule_level`  UInt8                           CODEC(ZSTD(1)),
    `wazuh_fired_times` UInt32                          CODEC(ZSTD(1)),
    `pci_dss`           String                          CODEC(ZSTD(3)),
    `gdpr`              String                          CODEC(ZSTD(3)),
    `hipaa`             String                          CODEC(ZSTD(3)),
    `nist_800_53`       String                          CODEC(ZSTD(3)),
    `attack_technique`  String                          CODEC(ZSTD(3)),
    `attack_id`         String                          CODEC(ZSTD(3)),
    `attack_tactic`     String                          CODEC(ZSTD(3)),
    `cve_id`            LowCardinality(String)          CODEC(ZSTD(1)),
    `cvss_score`        Float32                         CODEC(ZSTD(1)),
    `src_location`      String                          CODEC(ZSTD(3)),
    `decoder_name`      LowCardinality(String)          CODEC(ZSTD(1)),
    `manager_name`      LowCardinality(String)          CODEC(ZSTD(1)),
    `event_data`        String                          CODEC(ZSTD(3)),
    `extensions`        String                          CODEC(ZSTD(3)),
    `unmapped`          String                          CODEC(ZSTD(3)),
    `raw_data`          String                          CODEC(ZSTD(3)),
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
    INDEX idx_finding_uid   `finding_uid`   TYPE set(0)             GRANULARITY 4,
    INDEX idx_finding_title `finding_title` TYPE set(0)             GRANULARITY 4,
    INDEX idx_rule_name     `rule_name`     TYPE set(0)             GRANULARITY 4,
    INDEX idx_severity_id      `severity_id`      TYPE minmax       GRANULARITY 4,
    INDEX idx_wazuh_rule_level `wazuh_rule_level` TYPE minmax       GRANULARITY 4,
    INDEX idx_class_uid        `class_uid`        TYPE minmax       GRANULARITY 4,
    INDEX idx_type_uid         `type_uid`         TYPE minmax       GRANULARITY 4,
    INDEX idx_http_status      `http_status`      TYPE minmax       GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(time)
ORDER BY (class_uid, device_name, time){ttl}
SETTINGS
    index_granularity       = 4096,
    min_compress_block_size = 65536,
    max_compress_block_size = 1048576"#);

    ddl_client.query(&ddl).execute().await
        .with_context(|| format!("CREATE TABLE {table}"))?;

    let migrations = [
        format!("ALTER TABLE `{db_part}`.`{tbl_part}` ADD COLUMN IF NOT EXISTS `wazuh_rule_level`  UInt8  DEFAULT 0  CODEC(ZSTD(1))"),
        format!("ALTER TABLE `{db_part}`.`{tbl_part}` ADD COLUMN IF NOT EXISTS `wazuh_fired_times` UInt32 DEFAULT 0  CODEC(ZSTD(1))"),
        format!("ALTER TABLE `{db_part}`.`{tbl_part}` ADD COLUMN IF NOT EXISTS `pci_dss`           String DEFAULT '' CODEC(ZSTD(3))"),
        format!("ALTER TABLE `{db_part}`.`{tbl_part}` ADD COLUMN IF NOT EXISTS `gdpr`              String DEFAULT '' CODEC(ZSTD(3))"),
        format!("ALTER TABLE `{db_part}`.`{tbl_part}` ADD COLUMN IF NOT EXISTS `hipaa`             String DEFAULT '' CODEC(ZSTD(3))"),
        format!("ALTER TABLE `{db_part}`.`{tbl_part}` ADD COLUMN IF NOT EXISTS `nist_800_53`       String DEFAULT '' CODEC(ZSTD(3))"),
        format!("ALTER TABLE `{db_part}`.`{tbl_part}` ADD COLUMN IF NOT EXISTS `cve_id`            LowCardinality(String) DEFAULT '' CODEC(ZSTD(1))"),
        format!("ALTER TABLE `{db_part}`.`{tbl_part}` ADD COLUMN IF NOT EXISTS `cvss_score`        Float32 DEFAULT 0.0 CODEC(ZSTD(1))"),
    ];
    for stmt in &migrations {
        ddl_client.query(stmt).execute().await
            .with_context(|| format!("migration: {stmt}"))?;
    }

    Ok(())
}
