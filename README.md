# wazuh-ocsf-etl

A production-grade Wazuh → OCSF → ClickHouse pipeline written in Rust.

Reads `alerts.json` exactly like Filebeat reads a log file — tracking inode and byte offset — transforms every alert to the [OCSF 1.7.0](https://github.com/ocsf/ocsf-schema/releases/tag/v1.7.0) schema, and bulk-inserts into ClickHouse. Single 4.2 MB static binary, no JVM, no agents, no Elasticsearch.

```
Wazuh manager
  └─ /var/ossec/logs/alerts/alerts.json
        │  (inotify-free async tail)
        ▼
  wazuh-ocsf-etl  ──transform + classify──▶  ClickHouse
        │
        └─ state/alerts.pos   (inode + byte offset — survives restarts)
```

---

## Why this exists

Wazuh is excellent at detecting threats — but its native storage backend is **Elasticsearch / OpenSearch**, which is expensive (JVM, 8–32 GB RAM minimum), slow for analytics, and schema-less (every alert has different fields, making dashboards brittle).

This pipeline replaces the entire Elastic stack with a single binary:

| Problem (without this tool) | Solution |
|---|---|
| Raw Wazuh JSON — no schema, no standardisation | **OCSF 1.7.0** — every event gets `src_ip`, `actor_user`, `class_uid`, … in a vendor-neutral standard |
| Elasticsearch needs a JVM + 16–64 GB RAM | **ClickHouse** handles millions of events on 2 GB RAM |
| Filebeat → Logstash → Elasticsearch pipeline — 5 components | **One 4.2 MB static binary** — no JVM, no Kafka, no agents |
| Schema drift breaks Kibana dashboards on every rule change | Hot-reloadable `field_mappings.toml` — no restart required |
| Data loss on crash (Filebeat loses in-flight lines) | Inode + byte-offset state survives restarts and log rotation |
| Wazuh alerts locked in Elastic — no easy cross-vendor correlation | OCSF standard means Wazuh alerts can be JOINed with CrowdStrike, AWS CloudTrail, Okta and any other OCSF source |

### Cost and performance vs. the alternatives

| Solution | RAM needed | Schema standard | Config reload | Binary size |
|---|---|---|---|---|
| **This tool** | ~50 MB | OCSF 1.7.0 (latest) | Yes — 10 s | 4.2 MB |
| Wazuh + Elasticsearch stack | 16–64 GB (JVM) | None (raw JSON) | No — restart | N/A |
| Wazuh + Logstash pipeline | 4–8 GB (JVM) | Custom only | No — restart | N/A |
| Splunk forwarder | 4–8 GB | Partial | No | N/A |
| Matano (AWS-native) | Managed (Lambda) | ECS (not OCSF) | No | AWS required |

**ClickHouse compression advantage:** security data compresses 10–20× better in ClickHouse than in Elasticsearch. 1 TB of raw Wazuh alerts typically fits in 50–100 GB on disk. Analytical queries (`GROUP BY`, time-series, top-N attackers) run 10–100× faster than equivalent Elasticsearch aggregations.

### Why OCSF specifically

OCSF (Open Cybersecurity Schema Framework) is backed by AWS, Splunk, IBM, CrowdStrike, and 100+ vendors. Normalising to OCSF means:

- **Cross-tool correlation** — Wazuh alerts live in the same schema as CrowdStrike, AWS CloudTrail, or any OCSF source. JOIN them directly.
- **Interoperability** — any OCSF-aware SIEM, data lake, or dashboard consumes your data with zero re-mapping.
- **Future-proof** — if you switch from Wazuh to another EDR, the schema stays the same.

### Competitive landscape (as of March 2026)

A full GitHub search across `wazuh+ocsf+clickhouse`, `siem+ocsf+clickhouse`, and `security+events+ocsf+rust` returns **zero other public repositories** combining all three.

---

## Table of contents

1. [Requirements](#1-requirements)
2. [Build](#2-build)
3. [ClickHouse setup](#3-clickhouse-setup)
4. [Configure the pipeline](#4-configure-the-pipeline)
5. [Deploy as a systemd service](#5-deploy-as-a-systemd-service)
6. [ZeroMQ input mode (zero disk I/O)](#6-zeromq-input-mode-zero-disk-io)
7. [First-run behaviour (large existing files)](#7-first-run-behaviour-large-existing-files)
8. [Peak EPS tuning](#8-peak-eps-tuning)
9. [Custom field mappings & auto-column creation](#9-custom-field-mappings)
10. [Cloud / JSON-decoder source auto-mapping](#10-cloud--json-decoder-source-auto-mapping)
11. [Unmapped-field discovery](#11-unmapped-field-discovery)
12. [Log rotation](#12-log-rotation)
13. [Upgrading](#13-upgrading)
14. [Troubleshooting](#14-troubleshooting)
15. [OCSF class reference](#15-ocsf-class-reference)
16. [Wazuh rule fields in ClickHouse](#16-wazuh-rule-fields-in-clickhouse)
17. [Wazuh cluster deployment](#17-wazuh-cluster-deployment)
18. [OCSF schema validation](#18-ocsf-schema-validation)
19. [Field standardisation: 1,200+ decoder fields → 29 OCSF columns](#19-field-standardisation-1200-decoder-fields--29-ocsf-columns)
20. [Field mapping reference for Grafana dashboards](#20-field-mapping-reference-for-grafana-dashboards)

---

## 1. Requirements

| Component | Minimum version | Notes |
|---|---|---|
| **Rust toolchain** | 1.75+ stable | Only for building; not needed at runtime |
| **ClickHouse** | 22.x+ | HTTP interface must be reachable |
| **Wazuh manager** | 4.x | Needs `alerts.json` enabled |
| **OS** | Linux x86_64 | Tested on Ubuntu 22.04 / RHEL 9 |

Enable JSON alerts in Wazuh if not already on:

```xml
<!-- /var/ossec/etc/ossec.conf -->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
  </global>
</ossec_config>
```

Then restart: `systemctl restart wazuh-manager`

---

## 2. Build

```bash
# Clone / copy source
cd /root/rust-ocsf

# Release build (optimised, ~4.2 MB)
cargo build --release

# Binary location
ls -lh target/release/wazuh-ocsf-etl

# Run the test suite (119 unit tests)
cargo test
```

To cross-compile for a target without Rust installed, copy the single binary — it has no runtime dependencies.

---

## 3. ClickHouse setup

**No manual setup required.** On first start the binary automatically:

1. Creates the database (`CREATE DATABASE IF NOT EXISTS wazuh_ocsf`)
2. Creates each table the first time data arrives for that agent/location

Tables are created per-agent (e.g. `wazuh_ocsf.ocsf_web_server_01`) or per-source for shared locations (e.g. `wazuh_ocsf.ocsf_aws_cloudtrail`). All DDL uses `IF NOT EXISTS` so restarts and re-deployments are safe.

The only prerequisite is that the ClickHouse user has `CREATE DATABASE`, `CREATE TABLE`, and `INSERT` privileges on the target database. The default `default` user has all of these out of the box.

Each table uses:

- `MergeTree` engine with `ORDER BY (class_uid, device_name, time)` — lowest-cardinality column first for maximum primary key pruning
- `PARTITION BY toYYYYMM(time)` — monthly partitions (12/year), avoids partition explosion at high EPS
- `LowCardinality(String)` on all enum-like columns (severity, class, http_method, protocol, …) — 3–10× compression + faster GROUP BY
- `Delta+ZSTD` codecs on numeric sequences (ports, PIDs, byte counters, timestamps)
- `ZSTD(3)` on high-entropy strings (IPs, URLs, JSON blobs)
- `index_granularity = 4096` — finer granules for better skip-index selectivity
- Bloom-filter skip indexes on IPs, users, hostnames, filenames, URLs
- `minmax` skip indexes on `severity_id`, `class_uid`, `type_uid`, `http_status`
- Automatic TTL via `DATA_TTL_DAYS` (default 90 days)

---

## 4. Configure the pipeline

Create a `.env` file in the working directory (or set the variables as environment variables for systemd):

```bash
$EDITOR .env
```

### All environment variables

| Variable | Default | Description |
|---|---|---|
| `CLICKHOUSE_URL` | `http://localhost:8123` | ClickHouse HTTP endpoint |
| `CLICKHOUSE_DATABASE` | `wazuh_ocsf` | Target database |
| `CLICKHOUSE_USER` | `default` | ClickHouse username |
| `CLICKHOUSE_PASSWORD` | *(empty)* | ClickHouse password |
| `ALERTS_FILE` | `/var/ossec/logs/alerts/alerts.json` | Full path to Wazuh alerts JSON (FILE mode only) |
| `INPUT_MODE` | `file` | Input source: `file` or `zeromq` — only one active at a time |
| `ZEROMQ_URI` | `tcp://localhost:11111` | ZeroMQ URI to subscribe to (ZEROMQ mode only) |
| `STATE_FILE` | `state/alerts.pos` | Where to persist inode + byte offset |
| `SEEK_TO_END_ON_FIRST_RUN` | `true` | First-run behaviour — see [6](#6-first-run-behaviour-large-existing-files) |
| `BATCH_SIZE` | `5000` | Flush a per-table buffer once it reaches this many rows — tune up for high EPS |
| `FLUSH_INTERVAL_SECS` | `5` | Also flush on a timer when batch not yet full (low-EPS safety net) |
| `CHANNEL_CAP` | `50000` | Internal async queue depth between reader and writer (~1 KB/slot, ≈50 MB) |
| `SPECIAL_LOCATIONS` | *(empty)* | Comma-separated location names routed to shared tables |
| `DATA_TTL_DAYS` | `90` | Delete rows older than N days (empty = keep forever) |
| `STORE_RAW_DATA` | `true` | Store the full raw Wazuh alert JSON in `raw_data`. Set `false` to skip it — saves 40–70% table size with no loss of structured data |
| `UNMAPPED_FIELDS_FILE` | `state/unmapped_fields.json` | JSON report of `data.*` fields not yet mapped to OCSF columns — updated on every flush. See [11](#11-unmapped-field-discovery). |
| `OCSF_VALIDATE` | `true` | Run OCSF 1.7.0 schema checks after every transform. Violations are logged at `WARN` level — events are **always** forwarded to ClickHouse. Set `false` to disable during load testing. See [18](#18-ocsf-schema-validation). |
| `RUST_LOG` | `info` | Log level: `error`, `warn`, `info`, `debug`, `trace` |

### Minimal `.env` for a standard deployment

```dotenv
CLICKHOUSE_URL=http://clickhouse.internal:8123
CLICKHOUSE_DATABASE=wazuh_ocsf
CLICKHOUSE_USER=wazuh_etl
CLICKHOUSE_PASSWORD=strongpassword
ALERTS_FILE=/var/ossec/logs/alerts/alerts.json
DATA_TTL_DAYS=180
```

### `config/field_mappings.toml`

This file is **hot-reloaded every 10 seconds** — no restart needed.  
See [7](#7-custom-field-mappings) for details.

---

## 5. Deploy as a systemd service

### One-command install (recommended)

A bundled `install.sh` script handles every step — user creation, directory layout, `.env`, field mappings, and the systemd unit — in one shot.

```bash
# Make executable (only needed once)
chmod +x install.sh

# Run as root with the path to your binary
sudo ./install.sh /path/to/wazuh-ocsf-etl

# Example using the release build from this repo:
sudo ./install.sh ./target/release/wazuh-ocsf-etl
```

**What the script does (all 8 steps):**

| Step | Action |
|---|---|
| 1 | Validates the binary (ELF check) and installs it to `/usr/local/bin/wazuh-ocsf-etl` |
| 2 | Creates system user `wazuh-ocsf` (no login shell, home → `/opt/wazuh-ocsf`) |
| 3 | Creates `/opt/wazuh-ocsf/{config,state}` |
| 4 | Writes a fully-commented `.env` to `/opt/wazuh-ocsf/.env` (skipped if already present) |
| 5 | Deploys `config/field_mappings.toml` (skipped if already present — preserves customisations) |
| 6 | Sets ownership/permissions; adds `wazuh-ocsf` to the `wazuh` group for `alerts.json` access |
| 7 | Writes `/etc/systemd/system/wazuh-ocsf-etl.service` with security hardening |
| 8 | Runs `systemctl daemon-reload` and `systemctl enable wazuh-ocsf-etl` |

After the script completes:

```bash
# 1. Edit the config with your ClickHouse details
nano /opt/wazuh-ocsf/.env

# 2. Start the service
systemctl start wazuh-ocsf-etl

# 3. Check status
systemctl status wazuh-ocsf-etl

# 4. Watch live logs
journalctl -u wazuh-ocsf-etl -f
```

To uninstall:

```bash
sudo ./install.sh --uninstall
# Then optionally:
rm -rf /opt/wazuh-ocsf
userdel wazuh-ocsf
```

> **Re-running is safe.** If a `.env` or `field_mappings.toml` already exists the script skips those files, so re-running on an existing installation only updates the binary and service unit.

---

### Manual install (alternative)

#### Install the binary

```bash
install -m 755 target/release/wazuh-ocsf-etl /usr/local/bin/
```

#### Create a dedicated user

```bash
useradd -r -s /sbin/nologin -d /opt/wazuh-ocsf wazuh-ocsf
mkdir -p /opt/wazuh-ocsf/{state,config}
cp .env /opt/wazuh-ocsf/.env
cp config/field_mappings.toml /opt/wazuh-ocsf/config/
chown -R wazuh-ocsf:wazuh-ocsf /opt/wazuh-ocsf
```

The service user needs read access to `alerts.json`:

```bash
# Add wazuh-ocsf to the wazuh group (or set ACL)
usermod -aG wazuh wazuh-ocsf
# Confirm access
sudo -u wazuh-ocsf head -1 /var/ossec/logs/alerts/alerts.json
```

### systemd unit

Create `/etc/systemd/system/wazuh-ocsf-etl.service`:

```ini
[Unit]
Description=Wazuh → OCSF → ClickHouse ETL pipeline
After=network.target
# If ClickHouse runs on the same host:
# After=network.target clickhouse-server.service

[Service]
Type=simple
User=wazuh-ocsf
Group=wazuh-ocsf
WorkingDirectory=/opt/wazuh-ocsf
EnvironmentFile=/opt/wazuh-ocsf/.env
ExecStart=/usr/local/bin/wazuh-ocsf-etl
Restart=on-failure
RestartSec=5s

# Give the process time to drain the channel and flush on stop
TimeoutStopSec=30

# Hard limits
LimitNOFILE=65536
MemoryMax=512M

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/opt/wazuh-ocsf/state
ReadOnlyPaths=/var/ossec/logs/alerts /opt/wazuh-ocsf/config
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

### Enable and start

```bash
systemctl daemon-reload
systemctl enable --now wazuh-ocsf-etl
systemctl status wazuh-ocsf-etl
```

### Watch live logs

```bash
journalctl -u wazuh-ocsf-etl -f
```

Expected healthy startup output:

```
INFO wazuh_ocsf_etl: ── Wazuh → OCSF → ClickHouse ETL ───────────────────
INFO wazuh_ocsf_etl:   alerts_file      : /var/ossec/logs/alerts/alerts.json (size: 1024.3 MB)
INFO wazuh_ocsf_etl:   start_offset     : 1073741824  (0.0 MB to process)
INFO wazuh_ocsf_etl:   first_run_mode   : TAIL (start from end — existing data skipped)
INFO wazuh_ocsf_etl:   clickhouse       : http://clickhouse.internal:8123 / wazuh_ocsf
INFO wazuh_ocsf_etl:   batch_size       : 5000 rows  |  flush_interval: 5s
INFO wazuh_ocsf_etl: pipeline running — awaiting alerts …
```

---

## 6. ZeroMQ input mode (zero disk I/O)

### What it is

Instead of reading `alerts.json` from disk, the pipeline subscribes directly to the ZeroMQ PUB socket that `wazuh-analysisd` publishes every alert to — the moment it is generated, before it is even written to `alerts.json`.

```
FILE mode:   analysisd → disk write → alerts.json → poll → read → channel → ClickHouse
ZEROMQ mode: analysisd ──────────────────────────────────► channel → ClickHouse
```

### What it eliminates

| | FILE mode | ZEROMQ mode |
|---|---|---|
| Disk write by analysisd | Yes | Happens anyway (if enabled) but we don't read it |
| Disk read by this pipeline | Yes | **No** |
| Log rotation handling | Required | **Not needed** |
| State file / byte offset | Required | **Not needed** |
| 50 GB first-run problem | Needs protection | **Doesn't exist** |
| Latency per alert | ~50–100 ms (poll) | **~0 ms (push)** |
| Works from remote machine | No | **Yes** (`tcp://manager-ip:11111`) |
| Backpressure | Channel blocks reader | Channel blocks subscriber |
| Batching + ClickHouse insert | Same | Same |
| OCSF transform | Same | Same |

### Step 1 — Enable ZeroMQ on the Wazuh manager

```xml
<!-- /var/ossec/etc/ossec.conf on the Wazuh manager -->
<global>
  <zeromq_output>yes</zeromq_output>
  <!-- Bind to all interfaces if pipeline runs on a different machine,
       or localhost if collocated -->
  <zeromq_uri>tcp://0.0.0.0:11111/</zeromq_uri>
</global>
```

```bash
systemctl restart wazuh-manager
# Verify: should see "ZeroMQ output enabled" in /var/ossec/logs/ossec.log
grep -i zeromq /var/ossec/logs/ossec.log | tail -5
```

### Step 2 — Configure this pipeline

```dotenv
# /opt/wazuh-ocsf/.env
INPUT_MODE=zeromq
ZEROMQ_URI=tcp://localhost:11111     # or tcp://<manager-ip>:11111
```

### Step 3 — Open firewall (remote machine only)

```bash
# On the Wazuh manager (if pipeline runs on a different host)
firewall-cmd --permanent --add-port=11111/tcp
firewall-cmd --reload
```

### Step 4 — Restart the pipeline

```bash
systemctl restart wazuh-ocsf-etl
journalctl -u wazuh-ocsf-etl -f
# Expected: "ZeroMQ input: subscribed to tcp://..."
```

### Choosing between FILE and ZEROMQ

| Situation | Recommendation |
|---|---|
| Standard single-machine deployment | `INPUT_MODE=file` (default) — simpler, no Wazuh config change |
| High EPS (>5000/sec), need lowest latency | `INPUT_MODE=zeromq` |
| Pipeline on a separate machine from Wazuh | `INPUT_MODE=zeromq` — file mode can't work remotely |
| Wazuh manager doesn't support ZeroMQ output | `INPUT_MODE=file` |
| Want historical backfill of existing alerts.json | `INPUT_MODE=file` with `SEEK_TO_END_ON_FIRST_RUN=false` |

> **Note — delivery guarantee:** ZeroMQ PUB/SUB is **at-most-once**. If ClickHouse is slow and the pipeline's internal channel fills, ZeroMQ's per-subscriber send buffer overflows and messages are **silently dropped** — they cannot be recovered. FILE mode is **at-least-once** (the channel blocks the reader; nothing is dropped). Prefer FILE mode for any deployment where zero data loss matters.

> **Note — historical data:** ZeroMQ mode only delivers alerts generated after the subscription is established. If you need historical data from `alerts.json`, use FILE mode for the initial backfill, then switch to ZeroMQ.

---

## 7. First-run behaviour (large existing files)

This is the most important setting for production systems.

### Problem

On a Wazuh manager that has been running for months, `alerts.json` can be 50 GB or more. Without protection, a pipeline starting for the first time would read the entire file from byte 0 — stalling for hours or days before catching up to live data.

### How this pipeline handles it

The state file (`state/alerts.pos`) stores the last byte offset. On startup:

```
STATE FILE EXISTS?
│
├─ YES → lseek(saved_offset)          ← instant, O(1), just a syscall
│         Resume exactly where stopped
│
└─ NO  → FIRST RUN
          │
          ├─ SEEK_TO_END_ON_FIRST_RUN=true  (DEFAULT)
          │   lseek(file_size)
          │   Only new alerts from this moment onward are ingested
          │   50 GB is never read
          │
          └─ SEEK_TO_END_ON_FIRST_RUN=false
              lseek(0)
              Full historical backfill from the beginning
              WARNING: a 50 GB file will be read in full
```

The state file is saved **immediately** at startup when seeking to the end, so a `kill -9` before the first flush does not lose the position.

### Choosing the right mode

| Situation | Setting |
|---|---|
| New installation, existing file, only care about new alerts | `SEEK_TO_END_ON_FIRST_RUN=true` (default — no change needed) |
| New installation, want all historical data in ClickHouse | `SEEK_TO_END_ON_FIRST_RUN=false` |
| Any restart after the first run | Setting is ignored; saved offset is used |

### Deleting state to force a re-read

```bash
# Stop service first!
systemctl stop wazuh-ocsf-etl

# Delete state → next start is treated as first run
rm /opt/wazuh-ocsf/state/alerts.pos

# Set SEEK_TO_END_ON_FIRST_RUN=false in .env if you want full replay
systemctl start wazuh-ocsf-etl
```

---

## 8. Peak EPS tuning

The three variables below control exactly how batching works — same knobs as Logstash `pipeline.batch.size` / Filebeat `bulk_max_size`.

### How batching works

```
Reader task ──── line ────▶  mpsc channel (CHANNEL_CAP slots)
                                    │
                                    ▼
                           Processor task
                                    │
                     per-table in-memory Vec<OcsfRecord>
                                    │
                        flush trigger (whichever fires first):
                          ├── Vec reaches BATCH_SIZE rows   → flush now
                          └── FLUSH_INTERVAL_SECS timer     → flush now
                                    │
                                    ▼
                            ClickHouse HTTP INSERT
```

- **BATCH_SIZE** fires when a single table's buffer fills up — at high EPS every flush carries a full batch, minimising HTTP round-trips.
- **FLUSH_INTERVAL_SECS** fires even when the batch is not full — so at low EPS rows are never stuck in memory longer than this.
- **CHANNEL_CAP** is the in-flight buffer between the two async tasks. When ClickHouse is slow the channel fills and the reader task blocks — memory stays bounded and nothing is dropped.

### Recommended settings by EPS

| EPS (alerts/sec) | `BATCH_SIZE` | `FLUSH_INTERVAL_SECS` | `CHANNEL_CAP` |
|---|---|---|---|
| < 100 | 1000 | 5 | 50000 |
| 100 – 500 | 2000 | 5 | 50000 |
| 500 – 2000 | 5000 (default) | 5 | 50000 |
| 2000 – 10000 | 10000 | 3 | 100000 |
| > 10000 | 25000 | 2 | 200000 |

**Rule of thumb:** `CHANNEL_CAP` should be at least `BATCH_SIZE × 10` so the reader is never blocked by a single slow flush.

### Measuring your EPS

```bash
# Count lines written to alerts.json over 60 seconds
START=$(wc -l < /var/ossec/logs/alerts/alerts.json); sleep 60; END=$(wc -l < /var/ossec/logs/alerts/alerts.json); echo "EPS: $(( (END - START) / 60 ))"
```

Or query ClickHouse after a few minutes of ingestion:

```sql
SELECT
    toStartOfMinute(timestamp) AS minute,
    count() AS events,
    round(count() / 60) AS eps
FROM wazuh_ocsf.ocsf_my_server
WHERE timestamp >= now() - INTERVAL 10 MINUTE
GROUP BY minute
ORDER BY minute;
```

---

## 9. Custom field mappings

Edit `/opt/wazuh-ocsf/config/field_mappings.toml`. Changes are picked up within 10 seconds — no restart needed.

### Map a decoder field to a typed OCSF column

```toml
[field_mappings]
# Source field (from Wazuh alert "data" object) = Target OCSF column
"myapp.client_addr"   = "src_ip"
"myapp.server_addr"   = "dst_ip"
"myapp.current_user"  = "actor_user"
"myapp.threat_name"   = "rule_name"
```

Standard target column names: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `nat_src_ip`, `nat_dst_ip`, `nat_src_port`, `nat_dst_port`, `actor_user`, `target_user`, `domain`, `url`, `http_method`, `http_status`, `process_name`, `process_id`, `file_name`, `app_name`, `rule_name`, `app_category`, `action`, `status`, `interface_in`, `interface_out`, `src_hostname`, `dst_hostname`, `bytes_in`, `bytes_out`, `network_protocol`.

> **Note:** The column is named `app_category` (not `category`) to avoid confusion with OCSF's own event classification fields `category_uid` / `category_name`.

### Custom column auto-creation (zero manual DDL)

Any target name that is **not** in the standard OCSF list above is treated as a custom column. The pipeline handles it in two steps automatically — no `ALTER TABLE` or binary restart needed:

1. **The value is written into the `extensions` JSON column** on every insert (same as before).
2. **A dedicated ClickHouse column is automatically created** via `ALTER TABLE … ADD COLUMN IF NOT EXISTS` the first time the mapping is hot-reloaded after the config file is saved. The column is defined as:
   ```sql
   `my_custom_sensor` String
   MATERIALIZED JSONExtractString(extensions, 'my_custom_sensor')
   CODEC(ZSTD(3))
   ```
   The `MATERIALIZED` expression means ClickHouse extracts the value from `extensions` at insert time — no data is ever lost and old rows can be backfilled separately if needed.

```toml
[field_mappings]
# These targets don't exist yet → columns are auto-created within 10 s of saving this file
"data.my_custom_sensor" = "my_custom_sensor"
"data.ticket_id"        = "ticket_id"
"crowdstrike.sha256"    = "process_sha256"
"myapp.risk_score"      = "vendor_risk_score"
```

**What happens, step by step:**

| Step | When | What |
|---|---|---|
| 1 | Immediately (every event) | Value stored in `extensions` JSON — zero data loss even before DDL runs |
| 2 | ≤10 seconds (hot-reload) | Config watcher detects file change, new targets registered |
| 3 | Next flush | `ALTER TABLE … ADD COLUMN IF NOT EXISTS` runs on every existing `ocsf_*` table |
| 4 | Any new table created later | Column applied automatically as part of `ensure_table` |
| 5 | Retry on failure | If DDL fails (transient), the column stays unregistered and is retried on the next flush tick |

The operation is fully **idempotent** — `IF NOT EXISTS` means it is safe to call repeatedly and safe across restarts.

> **Column name safety:** Only alphanumeric characters and underscores are allowed in auto-created column names. Any other character in the target name is silently replaced with `_` before the DDL is issued, preventing SQL injection.

### Handle nested fields

Dot notation navigates JSON objects:

```toml
"myapp.network.client_ip"  = "src_ip"    # navigates myapp → network → client_ip
"myapp.client_ip"          = "src_ip"    # literal key match (exact, no navigation)
```

> **Do NOT add standard Wazuh module fields here.** The pipeline extracts these natively — zero TOML config needed:
>
> | Module | Fields extracted natively |
> |---|---|
> | **Vulnerability Detector** | `vulnerability.cve`, `vulnerability.cvss.cvss3.base_score`, `vulnerability.severity`, `vulnerability.reference`, `vulnerability.package.*` |
> | **Windows Event Log** | `win.system.providerName`, `win.system.processID`, `win.system.channel`, `win.system.eventID`, `win.eventdata.processName`, `win.eventdata.subjectUserName`, `win.eventdata.targetUserName`, … |
> | **dpkg / apt** | `data.package`, `data.dpkg_status`, `data.architecture` |
> | **Process context** | `data.uid`, `data.tty`, `data.pwd` |
>
> Adding these paths to `field_mappings.toml` has no effect — the native extraction block runs first and takes precedence. Only add entries for your own custom decoders or vendor integrations.

### OCSF schema migration (column renames)

When upgrading to a future OCSF version that renames columns:

```toml
[ocsf_field_renames]
"finding_title" = "finding.title"   # old_column = new_column
```

The binary will print the required `ALTER TABLE` statements at startup but will not execute them automatically.

---

---

## 10. Cloud / JSON-decoder source auto-mapping

When Wazuh ingests AWS, Azure, Okta, Zeek, or other cloud/vendor sources via its JSON decoder, the decoded fields land under `data.*` with vendor-specific field names. **No manual configuration is needed** — the ETL handles these sources automatically in two ways.

### Automatic OCSF class routing

The decoder name and rule groups are checked to assign the correct OCSF class, overriding the generic rules:

| Source | Decoder / group match | OCSF class_uid | OCSF class_name |
|---|---|---|---|
| AWS VPC Flow Logs | decoder `aws-vpcflow`, `vpc-flow*` | **4001** | Network Activity |
| AWS GuardDuty | decoder `aws-guardduty` or group `amazon-guardduty` | **2002** | Vulnerability Finding |
| AWS Inspector / Macie | group `amazon-inspector`, `amazon-macie` | **2002** | Vulnerability Finding |
| AWS Config | group `amazon-config` | **2003** | Compliance Finding |
| AWS WAF / ALB / S3 | group `amazon-waf`, `amazon-alb`, `amazon-s3` | **4002** | HTTP Activity |
| AWS Security Hub | decoder `aws-securityhub` | **2002** | Vulnerability Finding |
| AWS CloudTrail (IAM) | decoder `cloudtrail` AND group `aws_iam` or `authentication` | **3002** | Authentication |
| GCP Cloud Logging | decoder `gcp-pubsub`, `gcp_pubsub` or group `gcp` | **4001** | Network Activity |
| Microsoft Graph Security | decoder `ms-graph` | **2002** | Vulnerability Finding |
| Cloudflare WAF | decoder contains `cloudflare`; group `WAFAction` | **4002** | HTTP Activity |
| Okta System Log | decoder `okta` or group `okta` | **3002** | Authentication |
| Azure AD / Monitor | decoder `azure-ad`, `azure_ad` or group `azure-ad` | **3002** | Authentication |
| OneLogin | decoder `onelogin` or group `onelogin` | **3002** | Authentication |
| Zeek / Bro | decoder `zeek`, `bro-ids` or group `zeek`, `bro` | **4001** | Network Activity |
| Docker | decoder `docker` or group `docker` | **4001** | Network Activity |

### Automatic field extraction

All vendor-specific field paths are built into the static lookup tables — no TOML config required:

| OCSF column | Cloud field paths auto-resolved |
|---|---|
| `src_ip` | `srcAddr` (VPC Flow), `okta.client.ipAddress`, `azure.callerIpAddress`, `azure.properties.ipAddress`, `zeek.id.orig_h`, GuardDuty `remoteIpDetails.ipAddressV4`, `gcp.protoPayload.requestMetadata.callerIp`, `ClientIP` (Cloudflare) |
| `dst_ip` | `dstAddr` (VPC Flow), `zeek.id.resp_h`, GuardDuty `localIpDetails.ipAddressV4` |
| `src_port` | `srcPort` (VPC Flow, numeric), `zeek.id.orig_p`, GuardDuty `remotePortDetails.port` |
| `dst_port` | `dstPort` (VPC Flow, numeric), `zeek.id.resp_p`, GuardDuty `localPortDetails.port` |
| `actor_user` | `okta.actor.alternateId`, `okta.actor.displayName`, `azure.properties.userPrincipalName`, `aws.userIdentity.userName`, `gcp.protoPayload.authenticationInfo.principalEmail`, `office365.UserId`, `ms-graph.userPrincipalName` |
| `action` | `okta.displayMessage`, `okta.eventType`, `azure.operationName`, `aws.eventName`, `gcp.protoPayload.methodName`, `docker.Action`, `WAFAction` (Cloudflare) |
| `status` | `okta.outcome.result` (SUCCESS/FAILURE/ALLOW/DENY), `azure.resultType`, `audit.res`, `ms-graph.status`, `docker.status`, `aws.finding.Compliance.Status` |
| `bytes_in` | `aws.bytes` (VPC Flow), `aws.additionalEventData.bytesTransferredIn` (CloudTrail S3) |
| `interface_in` | `interfaceId` (VPC Flow ENI), `zeek._path` |
| `app_name` | `aws.eventSource`, `azure.resourceType`, `okta.client.userAgent.browser`, `gcp.resource.type`, `metadata.product.name` (Amazon Security Lake), `ms-graph.detectionSource`, `docker.Actor.Attributes.name` |
| `severity` | Numeric GuardDuty finding severity (0–10 → OCSF 1–5), string Inspector/Macie labels (Low/Medium/High/Critical), GCP 8-tier labels (EMERGENCY/ALERT/CRITICAL/ERROR/WARNING/NOTICE/INFO/DEBUG), Docker container status, MS Graph alert severity |
| `url` | `gcp.protoPayload.resourceName`, `aws.requestParameters.url`, `vulnerability.reference` |
| `domain` | `gcp.resource.labels.project_id`, `aws.userIdentity.accountId`, `azure.tenantId`, `github.org`, `office365.OrganizationName` |
| `rule_name` | `aws.title` (GuardDuty/Inspector finding title), `aws.finding.Compliance.SecurityControlId`, `ms-graph.title`, `threat.software.id` |

> **Numeric fields are handled correctly.** When the JSON decoder emits ports or byte counts as numbers (e.g. `"srcPort": 45678`), the pipeline converts them to the appropriate typed column. This covers all VPC Flow and Zeek numeric fields.

### Cloud / vendor source field extraction (natively extracted — zero config)

The pipeline contains dedicated extraction blocks for each of the following vendor sources. No `field_mappings.toml` entries are required.

#### AWS (all 10+ sources)

| Source | Native extraction covers |
|---|---|
| CloudTrail | `userIdentity.userName/arn`, `eventName`, `errorCode`, `sourceIPAddress`, `requestParameters.*` |
| GuardDuty | Finding severity (numeric 0–10), title, type, `remoteIpDetails.ipAddressV4`, `localIpDetails.ipAddressV4` |
| Inspector / Macie | Severity label, finding title, `assetAttributes.hostname` |
| VPC Flow Logs | `srcaddr`, `dstaddr`, `srcport`, `dstport`, `protocol`, `bytes`, `action`, `interfaceId` |
| WAF | `httpRequest.clientIp`, `httpRequest.uri`, `httpRequest.httpMethod`, `webaclId`, `action` |
| ALB / ELB | `clientIp`, `targetIp`, `requestUrl`, `requestProcessingTime`, `elb_status_code`, `sentBytes`, `receivedBytes` |
| S3 Server Access | `remoteip`, `requester`, `key`, `operation`, `httpStatus`, `bytesSent`, `request_uri` |
| Config | `awsAccountId`, `resourceType`, `resourceId`, `configurationItemStatus`, `configuration.complianceType` |
| Security Hub | `finding.Title`, `finding.ProductName`, `finding.Compliance.Status`, `finding.RecordState`, `finding.Compliance.SecurityControlId` |
| Trusted Advisor | `check-name`, `status`, `resourceId` |
| KMS | `requestParameters.keyId`, `errorCode` |

#### GCP Cloud Logging

| GCP field | OCSF column |
|---|---|
| `protoPayload.authenticationInfo.principalEmail` | `actor_user` |
| `protoPayload.requestMetadata.callerIp` | `src_ip` |
| `protoPayload.methodName` | `action` |
| `protoPayload.resourceName` | `url` |
| `resource.labels.project_id` | `domain` |
| `severity` (EMERGENCY/ALERT/CRITICAL/ERROR/WARNING/NOTICE/INFO/DEBUG) | `severity` / `severity_id` override |

#### Docker

| Docker field | OCSF column |
|---|---|
| `docker.Action` | `action` |
| `docker.Type` | `app_category` |
| `docker.Actor.Attributes.name` | `app_name` |
| `docker.level` (`error`/`warning`/`info`) | `severity` / `severity_id` override |
| `docker.Actor.Attributes.role.new` / `role.old` | `extensions.docker_role_new` / `docker_role_old` |

#### Microsoft Graph Security

| MS Graph field | OCSF column |
|---|---|
| `ms-graph.severity` | `severity` / `severity_id` override |
| `ms-graph.title` | `rule_name` |
| `ms-graph.category` | `app_category` |
| `ms-graph.status` | `status` |
| `ms-graph.detectionSource` / `serviceSource` | `app_name` |

#### Office365

| Office365 field | OCSF column | Notes |
|---|---|---|
| `office365.UserId` | `actor_user` | User performing the action |
| `office365.ClientIP` / `ClientIPAddress` | `src_ip` | Connecting client IP |
| `office365.Operation` | `action` | Operation performed |
| `office365.OrganizationName` / `OrganizationId` | `domain` | Tenant name / UUID |
| `office365.Workload` / `ApplicationDisplayName` | `app_name` | Exchange / SharePoint / Teams / … |
| `office365.ObjectId` / `SiteUrl` | `url` | Affected resource URL |
| `office365.ResultStatus` | `status` | Succeeded / Failed / PartiallySucceeded |
| `office365.InternalLogonType` | `app_category` | Exchange logon classification integer (0=Owner, 1=Delegate, 2=Admin) |
| `office365.LogonType` | `app_category` | Azure AD logon type integer — same concept as `win.eventdata.logonType` |

---

### Standard Wazuh module fields (natively extracted — zero config)

Standard Wazuh modules produce structured fields that are extracted in code. No `field_mappings.toml` entries are needed or recognised for these paths.

#### Vulnerability Detector (OCSF class 2002)

| Wazuh alert field | OCSF column / extension | Notes |
|---|---|---|
| `vulnerability.cve` | **`cve_id`** (`LowCardinality(String)`) | CVE identifier — e.g. `"CVE-2025-61984"` |
| `vulnerability.cvss.cvss3.base_score` | **`cvss_score`** (`Float32`) | CVSS v3 base score 0.0–10.0 |
| `vulnerability.severity` | **`severity` / `severity_id`** | Scanner label overrides rule-level mapping (Low/Medium/High/Critical → 2/3/4/5) |
| `vulnerability.reference` | **`url`** | Advisory / patch URL |
| `vulnerability.package.name` | **`app_name`** | Affected package |
| `vulnerability.status` | **`status`** | e.g. `"Active"`, `"Obsolete"` |

#### Windows Event Log (OCSF class auto-detected)

| Wazuh alert field | OCSF column / extension | Notes |
|---|---|---|
| `win.system.providerName` | **`app_name`** | e.g. `"Microsoft-Windows-Security-Auditing"` |
| `win.system.processID` | **`process_id`** | Event-generating process PID |
| `win.system.eventID` | **`extensions.win_event_id`** | Windows Event ID — e.g. `"4624"` |
| `win.system.channel` | **`extensions.win_channel`** | e.g. `"Security"`, `"Application"` |
| `win.eventdata.processName` | **`process_name`** | |
| `win.eventdata.subjectUserName` | **`actor_user`** | Falls back to `subjectUserSid` |
| `win.eventdata.targetUserName` | **`target_user`** | Falls back to `targetUserSid` |
| `win.eventdata.logonType` | **`extensions.win_logon_type`** | e.g. `"3"` (Network) |

#### dpkg / apt (package management)

| Wazuh alert field | OCSF column / extension | Notes |
|---|---|---|
| `data.package` | **`app_name`** | Package being installed/removed |
| `data.dpkg_status` | **`status`** | e.g. `"installed"`, `"removed"` |
| `data.version` | **`extensions.package_version`** | |
| `data.architecture` | **`extensions.package_arch`** | |

#### Process context (sudo, audit)

| Wazuh alert field | OCSF column / extension | Notes |
|---|---|---|
| `data.uid` | **`extensions.actor_uid`** | Numeric UID |
| `data.gid` | **`extensions.actor_gid`** | Numeric GID |
| `data.home` | **`extensions.actor_home_dir`** | Home directory |
| `data.shell` | **`extensions.actor_shell`** | Login shell |
| `data.tty` | **`extensions.tty`** | Terminal device |
| `data.pwd` | **`extensions.working_dir`** | Current working directory |
| `data.file` | **`file_name`** | File name from generic decoder |
| `audit.euid` | **`extensions.audit_euid`** | Effective UID (auditd) |
| `audit.uid` | **`extensions.audit_uid`** | Real UID (auditd) |
| `audit.gid` | **`extensions.audit_gid`** | Real GID (auditd) |
| `audit.session` | **`extensions.audit_session`** | Audit session ID |

### For fields not yet covered

Any field the pipeline sees but doesn't recognise is automatically recorded in `state/unmapped_fields.json`. See [11](#11-unmapped-field-discovery).

---

## 11. Unmapped-field discovery

Every `data.*` field path present in a live alert that is **not** already covered by a built-in constant or a custom `field_mappings.toml` entry is recorded automatically. This gives operators a continuously-updated list of fields they can promote to typed OCSF columns.

> **Standard Wazuh module fields are never reported here.** The 150+ paths from `vulnerability.*`, `win.system.*`, `win.eventdata.*`, dpkg fields, process context (`uid`, `gid`, `tty`, `pwd`, `home`, `shell`), audit fields (`audit.euid`, `audit.uid`, `audit.gid`, `audit.session`), SCA fields (`sca.check.*`, `sca.policy_id`, etc.), and AWS CloudTrail fields are all natively extracted and are excluded from the unmapped report. Only truly unrecognised custom decoder fields appear.

### The report file

After every successful ClickHouse flush, the pipeline writes `state/unmapped_fields.json` (configurable via `UNMAPPED_FIELDS_FILE`):

```json
{
  "note": "Fields from data.* that are not yet mapped to an OCSF typed column. Add entries to config/field_mappings.toml to promote them.",
  "fields": [
    "edr.threat.name",
    "pan.app_category"
  ]
}
```

Fields are sorted by frequency — the most frequently occurring unmapped fields appear first.

### Archival on restart

On each startup, the previous session's report is automatically renamed to  
`state/unmapped_fields.YYYYMMDDTHHMMSSZ.bak` before a fresh report begins accumulating.  
Historical discoveries are never silently lost — check the `.bak` files to see what prior runs observed.

### Startup log

On startup, if a prior report exists, the top 10 unmapped fields are printed to the log — no file inspection needed:

```
INFO   top unmapped fields (add to field_mappings.toml): ["edr.threat.name", "pan.app_category", ...]
```

### Acting on the report

1. Open `state/unmapped_fields.json` (or a `.bak` archive for a past session)
2. For each field you want to promote, add an entry to `config/field_mappings.toml`
3. Choose the correct target column (see [4 of FIELD_MAPPINGS.md](FIELD_MAPPINGS.md) for valid targets)
4. Save — hot-reload picks it up within 10 seconds
5. That field will stop appearing in future reports and will be written to a typed ClickHouse column

```toml
[field_mappings]
# From the unmapped report:
"edr.threat.name"          = "rule_name"
"edr.network.remote_ip"    = "dst_ip"
"edr.network.remote_port"  = "dst_port"
"pan.app_category"         = "app_category"
"pan.bytes_total"          = "bytes_in"
"myapp.user_email"         = "actor_user"
"myapp.risk_score"         = "vendor_risk_score"   # → extensions{}
```

> Fields mapped to an **unknown target** (like `vendor_risk_score`) are written to the `extensions` JSON column rather than a typed column — useful for vendor-specific data you want to preserve but don't need to index.

---

## 12. Log rotation

Wazuh rotates `alerts.json` daily by default (renaming it to `alerts.json-YYYYMMDD.gz` and creating a new empty file). This pipeline handles rotation correctly in all cases:

### Rotation while the pipeline is running

- `FileTailer` checks the file's inode and current size on every EOF poll
- When the inode changes or the file shrinks, rotation is detected
- The tailer re-opens the new file from byte 0 automatically
- No alerts are lost and no alerts are double-processed

### Rotation while the pipeline is stopped

- On startup, the saved inode in `state/alerts.pos` is compared to the current file's inode
- If they differ, the file has been rotated while the service was down
- The pipeline resets to offset 0 and reads the new file from the beginning
- Alerts written to the old file after the last flush are not replayed (they were already rotated away)

To ensure minimal data loss during planned maintenance, always stop the pipeline gracefully — it will drain the in-memory channel and do a final flush before exiting:

```bash
systemctl stop wazuh-ocsf-etl   # sends SIGTERM → graceful drain
```

---

## 13. Upgrading

### Using install.sh (recommended)

Re-running `install.sh` is safe — it stops the service, replaces the binary, updates the systemd unit, and restarts. Your `.env` and `field_mappings.toml` are **never overwritten**.

```bash
# Build new binary
cargo build --release

# Re-run installer — updates binary + service unit only
sudo ./install.sh ./target/release/wazuh-ocsf-etl

# Start the service
systemctl start wazuh-ocsf-etl
journalctl -u wazuh-ocsf-etl -f
```

### Manual upgrade

```bash
# 1. Build new binary
cargo build --release

# 2. Stop service gracefully (drains + saves state)
systemctl stop wazuh-ocsf-etl

# 3. Replace binary
install -m 755 target/release/wazuh-ocsf-etl /usr/local/bin/

# 4. Copy updated field_mappings if needed
cp config/field_mappings.toml /opt/wazuh-ocsf/config/

# 5. Start
systemctl start wazuh-ocsf-etl
journalctl -u wazuh-ocsf-etl -f
```

The state file is not affected — the pipeline resumes from the last saved offset.

---

## 14. Troubleshooting

### Service fails to start

```bash
journalctl -u wazuh-ocsf-etl -n 50 --no-pager
```

**`Permission denied` on `alerts.json`**

```bash
# Verify access
sudo -u wazuh-ocsf cat /var/ossec/logs/alerts/alerts.json | head -1

# Fix: add service user to wazuh group
usermod -aG wazuh wazuh-ocsf
systemctl restart wazuh-ocsf-etl
```

**`Connection refused` to ClickHouse**

```bash
# Test connectivity from the service host
curl -s "http://clickhouse.internal:8123/ping"   # should return "Ok."

# Check ClickHouse is listening
ss -tlnp | grep 8123
```

**`Authentication failed` for ClickHouse**

Check `CLICKHOUSE_USER` and `CLICKHOUSE_PASSWORD` in `.env`. Verify the user exists and has write permissions on the database:

```sql
GRANT INSERT, CREATE TABLE ON wazuh_ocsf.* TO wazuh_etl;
```

---

### No data in ClickHouse

**Check the pipeline is receiving alerts:**

```bash
# Should increment every few seconds on an active Wazuh manager
journalctl -u wazuh-ocsf-etl -f | grep -E "flushed|rows"
```

**Check the alerts file is being written to:**

```bash
tail -f /var/ossec/logs/alerts/alerts.json | head -5
```

**Check state file:**

```bash
cat /opt/wazuh-ocsf/state/alerts.pos
# inode=12345678
# offset=1073741824
```

If `offset` equals the current file size the pipeline is caught up — new rows will appear as new alerts arrive.

**Check which tables exist:**

```sql
-- In ClickHouse
SHOW TABLES FROM wazuh_ocsf;
SELECT table, sum(rows) AS rows, formatReadableSize(sum(bytes)) AS size
FROM system.parts
WHERE database = 'wazuh_ocsf' AND active
GROUP BY table
ORDER BY rows DESC;
```

---

### Pipeline is far behind (high catch-up gap)

On restart the startup log shows how far behind the pipeline is:

```
INFO   catch_up : 8192.4 MB written while service was stopped
```

This is normal — the pipeline will work through the backlog as fast as ClickHouse can accept inserts. To monitor progress:

```bash
watch -n 2 'cat /opt/wazuh-ocsf/state/alerts.pos'
```

The `offset` number should increase steadily. ClickHouse insert throughput can be measured with:

```sql
SELECT event_time, query_duration_ms, written_rows
FROM system.query_log
WHERE type = 'QueryFinish' AND query LIKE 'INSERT INTO wazuh_ocsf%'
ORDER BY event_time DESC
LIMIT 20;
```

---

### Duplicate rows after an unclean shutdown

This pipeline provides **at-least-once** delivery. After a `kill -9` or power loss, the last unflushed batch (up to `BATCH_SIZE` rows) may be re-processed on the next start.

To deduplicate in ClickHouse, use a `ReplacingMergeTree` or query with `FINAL`:

```sql
SELECT * FROM wazuh_ocsf.ocsf_web_server_01 FINAL
WHERE timestamp >= now() - INTERVAL 1 HOUR;
```

Or force deduplication (expensive on large tables, run off-peak):

```sql
OPTIMIZE TABLE wazuh_ocsf.ocsf_web_server_01 FINAL;
```

---

### High memory usage

The in-memory channel holds up to 50,000 lines. If ClickHouse is slow or unavailable the channel fills and the reader task blocks — memory stays bounded. Check ClickHouse health:

```bash
curl -s "http://clickhouse.internal:8123/?query=SELECT+1"
```

---

### Enable debug logging

```bash
# Edit .env or override inline
RUST_LOG=debug systemctl restart wazuh-ocsf-etl
journalctl -u wazuh-ocsf-etl -f
```

`RUST_LOG=trace` also prints every line read from the file — very verbose, use only on dev.

---

### Force a full historical re-ingest

```bash
systemctl stop wazuh-ocsf-etl
rm /opt/wazuh-ocsf/state/alerts.pos

# In /opt/wazuh-ocsf/.env set:
#   SEEK_TO_END_ON_FIRST_RUN=false

systemctl start wazuh-ocsf-etl
journalctl -u wazuh-ocsf-etl -f
# Watch: "first_run_mode : REPLAY (reading from byte 0 — full historical ingest)"
```

---

### Reset to current end of file (discard backlog)

```bash
systemctl stop wazuh-ocsf-etl
rm /opt/wazuh-ocsf/state/alerts.pos

# In /opt/wazuh-ocsf/.env ensure:
#   SEEK_TO_END_ON_FIRST_RUN=true   (this is the default)

systemctl start wazuh-ocsf-etl
# Watch: "first_run_mode : TAIL (start from end — existing data skipped)"
```

---

## 15. OCSF class reference

Every alert is automatically classified. The class is written to the `class_uid` and `class_name` columns in ClickHouse.

| `class_uid` | `class_name` | `category_uid` | Triggered by |
|---|---|---|---|
| 1001 | File System Activity | 1 | `syscheck`, `sysmon_file` rule groups |
| 1006 | Process Activity | 1 | `sysmon_process`, `execve`, `audit_command` groups |
| 2002 | Vulnerability Finding | 2 | `vulnerability-detector` group; decoder `aws-guardduty` / group `amazon-guardduty` |
| 2003 | Compliance Finding | 2 | `sca`, `oscap`, `ciscat` groups |
| 2004 | Detection Finding | 2 | **Default** — all rules not matched above |
| 3001 | Account Change | 3 | `adduser`, `userdel`, `usermod` groups |
| 3002 | Authentication | 3 | `sshd`, `pam`, `sudo`, `authentication*` groups; decoder `okta`, `azure-ad`; CloudTrail + `aws_iam` group |
| 4001 | Network Activity | 4 | `firewall`, `suricata`, `fortigate`, `snort`, `pfsense` decoders; decoder `aws-vpcflow`, `zeek`, `bro-ids` |
| 4002 | HTTP Activity | 4 | `nginx`, `apache`, `iis` decoders; `web*` groups |
| 4003 | DNS Activity | 4 | `named`, `dns` decoders |
| 4004 | DHCP Activity | 4 | `dhcpd` decoder; `dhcp` group |

### `activity_id` values per class

Each class has a specific set of valid `activity_id` values. Below are the classes with non-trivial activity routing.

**File System Activity (1001):**

| `activity_id` | Meaning | Trigger |
|---|---|---|
| 1 | Create | `syscheck.event = "added"` |
| 2 | Read | `syscheck.event = "read"` |
| 3 | Update | `syscheck.event = "modified"` |
| 4 | Delete | `syscheck.event = "deleted"` |
| 5 | Rename | `syscheck.event = "renamed"` or `"moved"` |

**DNS Activity (4003):**

| `activity_id` | Meaning | Trigger |
|---|---|---|
| 1 | Query | default (outgoing lookup) |
| 2 | Response | rule group `dns_response`, or action contains `"response"` / `"answer"` |
| 3 | Traffic | action contains `"traffic"` |

**DHCP Activity (4004):**

| `activity_id` | Meaning | Trigger |
|---|---|---|
| 1 | Assign | `DHCPACK`, `"ack"`, `"assigned"` (default) |
| 2 | Renew | `DHCPREQUEST`, `"request"`, `"renew"`, `"rebind"` |
| 3 | Release | `DHCPRELEASE`, `"release"` |
| 4 | Error | `DHCPNAK`, `"nak"`, `"nack"`, `"error"` |

---

### `status_id` values per OCSF class

OCSF 1.7.0 defines **different** `status_id` enums depending on the class profile:

**Finding classes** (class_uid 2002, 2003, 2004 — Detection / Vulnerability / Compliance):

| `status_id` | Meaning | When set |
|---|---|---|
| 0 | Unknown | status field empty |
| 1 | New | **Default for all Wazuh findings** |
| 2 | In Progress | status contains `in_progress`, `investigating` |
| 3 | Suppressed | status contains `suppressed`, `benign`, `false_positive` |
| 4 | Resolved | status contains `resolved`, `closed`, `remediated` |
| 5 | Archived | status = `archived` |
| 6 | Deleted | status = `deleted` |

**Operational classes** (all other class_uids — Auth, Network, File, Process, HTTP, DNS, DHCP):

| `status_id` | Meaning | When set |
|---|---|---|
| 0 | Unknown | status field empty |
| 1 | Success | status = `success`, `allow`, `pass`, `passed` |
| 2 | Failure | status = `failure`, `fail`, `deny`, `block`, `drop`, `reject` |
| 99 | Other | any other non-empty value |

---

## 16. Wazuh rule fields in ClickHouse

Every Wazuh rule field is preserved in the OCSF schema. Here is the exact mapping so SOC analysts know which column to query:

### Core rule identity

| Wazuh alert field | ClickHouse column | Type | Description |
|---|---|---|---|
| `rule.id` | **`finding_uid`** | `LowCardinality(String)` | Wazuh rule ID — e.g. `"5763"`. Primary key for rule-based searches. |
| `rule.description` | **`finding_title`** | `String` | Human-readable rule description — e.g. `"SSH brute force attack"`. |
| `rule.level` | **`wazuh_rule_level`** | `UInt8` | Raw Wazuh severity level 1–15. Stored alongside `severity_id` so you can filter `WHERE wazuh_rule_level >= 12`. |
| `rule.groups` | **`finding_types`** | `String` (JSON array) | All rule groups as a JSON array — e.g. `["sshd","authentication_failed","brute_force"]`. |
| `rule.firedtimes` | **`wazuh_fired_times`** | `UInt32` | Number of times this rule fired in the analysis window — repeated bursts show up immediately. |
| `decoder.name` | **`decoder_name`** | `LowCardinality(String)` | The Wazuh decoder that parsed the raw log — e.g. `"sshd"`, `"auditd"`, `"windows_eventchannel"`. |

### MITRE ATT&CK

| Wazuh alert field | ClickHouse column | Type | Description |
|---|---|---|---|
| `rule.mitre.technique` | **`attack_technique`** | `String` | Technique name — e.g. `"Brute Force"`. |
| `rule.mitre.id` | **`attack_id`** | `String` | Technique ID — e.g. `"T1110"`. |
| `rule.mitre.tactic` | **`attack_tactic`** | `String` | Tactic name — e.g. `"Credential Access"`. |

### Vulnerability Finding fields (class 2002)

Populated automatically when `vulnerability-detector` fires. No config required.

| Source field | ClickHouse column | Type | Description |
|---|---|---|---|
| `vulnerability.cve` | **`cve_id`** | `LowCardinality(String)` | CVE identifier — e.g. `"CVE-2025-61984"`. |
| `vulnerability.cvss.cvss3.base_score` | **`cvss_score`** | `Float32` | CVSS v3 base score 0.0–10.0. |
| `vulnerability.severity` (scanner label) | **`severity` / `severity_id`** | `String` / `UInt8` | Overrides the default rule-level mapping. Scanner labels Low/Medium/High/Critical map to severity_id 2/3/4/5. |
| `vulnerability.reference` | **`url`** | `String` | Advisory or patch URL. |
| `vulnerability.package.name` | **`app_name`** | `LowCardinality(String)` | Affected package name. |
| `vulnerability.status` | **`status`** | `String` | e.g. `"Active"`, `"Obsolete"`. |

### Extensions column

Fields that don't map to a dedicated typed column are written to the `extensions` JSON column. Standard Wazuh module fields stored there:

| Source field | `extensions` key | Notes |
|---|---|---|
| `win.system.eventID` | `win_event_id` | Windows Event ID |
| `win.system.channel` | `win_channel` | e.g. `"Security"` |
| `win.eventdata.logonType` | `win_logon_type` | e.g. `"3"` (Network) |
| `data.version` (dpkg) | `package_version` | |
| `data.architecture` (dpkg) | `package_arch` | |
| `data.uid` | `actor_uid` | Numeric UID |
| `data.gid` | `actor_gid` | Numeric GID |
| `data.home` | `actor_home_dir` | Home directory |
| `data.shell` | `actor_shell` | Login shell |
| `data.tty` | `tty` | Terminal device |
| `data.pwd` | `working_dir` | Working directory |
| `audit.euid` | `audit_euid` | Effective UID (auditd) |
| `audit.uid` | `audit_uid` | Real UID (auditd) |
| `audit.gid` | `audit_gid` | Real GID (auditd) |
| `audit.session` | `audit_session` | Audit session ID |

### Compliance tags

Each column stores the framework-specific IDs as a comma-separated string (one row per alert). Use `LIKE` or `has()` on the array to filter.

| Wazuh alert field | ClickHouse column | Example value |
|---|---|---|
| `rule.pci_dss` | **`pci_dss`** | `"10.2.4,10.2.5"` |
| `rule.gdpr` | **`gdpr`** | `"IV_35.7.d"` |
| `rule.hipaa` | **`hipaa`** | `"164.312.b"` |
| `rule.nist_800_53` | **`nist_800_53`** | `"AU-14,AC-7"` |

### OCSF severity mapping

| Wazuh `rule.level` | `severity_id` | `severity` |
|---|---|---|
| 0 | 0 | Unknown |
| 1–3 | 1 | Informational |
| 4–6 | 2 | Low |
| 7–9 | 3 | Medium |
| 10–12 | 4 | High |
| 13–15 | 5 | Critical |

---

### SOC query cookbook

```sql
-- Hunt by Wazuh rule ID (what a SOC analyst already knows)
SELECT time, device_name, actor_user, src_ip, finding_title, wazuh_rule_level
FROM wazuh_ocsf.ocsf_my_server
WHERE finding_uid = '5763'
ORDER BY time DESC
LIMIT 50;

-- All high/critical Wazuh rules (level 10+) in the last 24 hours
SELECT finding_uid, finding_title, count() AS hits, max(wazuh_rule_level) AS max_level
FROM wazuh_ocsf.ocsf_my_server
WHERE wazuh_rule_level >= 10
  AND time >= now() - INTERVAL 24 HOUR
GROUP BY finding_uid, finding_title
ORDER BY hits DESC
LIMIT 20;

-- Rules that fired repeatedly (burst detection)
SELECT finding_uid, finding_title, src_ip, wazuh_fired_times
FROM wazuh_ocsf.ocsf_my_server
WHERE wazuh_fired_times > 5
  AND time >= now() - INTERVAL 1 HOUR
ORDER BY wazuh_fired_times DESC;

-- Find by rule group (e.g. all brute_force group alerts)
SELECT time, finding_uid, finding_title, src_ip, actor_user
FROM wazuh_ocsf.ocsf_my_server
WHERE finding_types LIKE '%brute_force%'
  AND time >= today()
ORDER BY time DESC;

-- Find by decoder (e.g. all events parsed by auditd)
SELECT time, finding_uid, finding_title, actor_user, file_name
FROM wazuh_ocsf.ocsf_my_server
WHERE decoder_name = 'auditd'
  AND time >= now() - INTERVAL 6 HOUR
ORDER BY time DESC;

-- MITRE ATT&CK: all Credential Access events
SELECT time, finding_uid, finding_title, attack_id, attack_technique, src_ip
FROM wazuh_ocsf.ocsf_my_server
WHERE attack_tactic LIKE '%Credential Access%'
  AND time >= now() - INTERVAL 24 HOUR
ORDER BY time DESC;

-- PCI DSS compliance: rules covering requirement 10
SELECT finding_uid, finding_title, count() AS hits
FROM wazuh_ocsf.ocsf_my_server
WHERE pci_dss LIKE '%10.%'
  AND time >= now() - INTERVAL 7 DAY
GROUP BY finding_uid, finding_title
ORDER BY hits DESC;

-- Authentication events in the last hour
SELECT time, device_name, actor_user, src_ip, severity, finding_title
FROM wazuh_ocsf.ocsf_my_server
WHERE class_uid = 3002
  AND time >= now() - INTERVAL 1 HOUR
ORDER BY time DESC
LIMIT 100;

-- Top source IPs hitting the firewall today
SELECT src_ip, count() AS attempts
FROM wazuh_ocsf.ocsf_my_firewall
WHERE class_uid = 4001
  AND time >= today()
GROUP BY src_ip
ORDER BY attempts DESC
LIMIT 20;
```

---

## Behaviour summary

| Scenario | Behaviour |
|---|---|
| First start, large existing file | Seek to end instantly — no replay (default) |
| First start, want all history | Set `SEEK_TO_END_ON_FIRST_RUN=false` |
| Restart after clean stop | Resume from exact saved byte offset |
| Restart after `kill -9` | Re-process at most one batch (at-least-once) |
| Log rotation while running | Auto-detected by inode change, re-opens new file |
| Log rotation while stopped | Inode mismatch detected on startup, reads new file from 0 |
| ClickHouse slow or down | Channel fills → reader blocks → no memory explosion, no data loss |
| SIGTERM / `systemctl stop` | Drains channel → final flush → saves offset → clean exit |

---

## 17. Wazuh cluster deployment

### How a Wazuh cluster works

In a Wazuh cluster every node (master + workers) runs its own `wazuh-analysisd` and writes to its **own local** `/var/ossec/logs/alerts/alerts.json`. There is no central alerts file. Agents are assigned to workers for analysis; the master handles manager-level events (vulnerability scans, SCA, inventory).

```
┌──────────────────────────────────────────────────────────────────────┐
│  Wazuh cluster                                                       │
│                                                                      │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐               │
│  │  MASTER     │   │  WORKER-1   │   │  WORKER-N   │               │
│  │  analysisd  │   │  analysisd  │   │  analysisd  │               │
│  │  alerts.json│   │  alerts.json│   │  alerts.json│               │
│  └──────┬──────┘   └──────┬──────┘   └──────┬──────┘               │
│         │                 │                  │                       │
│  ┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐               │
│  │  ETL        │   │  ETL        │   │  ETL        │               │
│  │  instance-0 │   │  instance-1 │   │  instance-N │               │
│  └──────┬──────┘   └──────┬──────┘   └──────┬──────┘               │
│         └─────────────────┴──────────────────┘                      │
│                            │                                         │
└────────────────────────────▼─────────────────────────────────────────┘
                    ClickHouse (shared)
                    wazuh_ocsf database
```

### Deploy one ETL instance per Wazuh node

Install the same binary on every node. Each instance reads from its **local** `alerts.json` and writes to the same shared ClickHouse server.

**Run on each node (master and every worker):**

```bash
# Copy binary
install -m 755 wazuh-ocsf-etl /usr/local/bin/

# Working dir — per-node name prevents state file collisions
export NODE=wazuh-master   # change to: wazuh-worker-1, wazuh-worker-2 …
mkdir -p /opt/wazuh-ocsf-${NODE}/{state,config}
useradd -r -s /sbin/nologin -d /opt/wazuh-ocsf-${NODE} wazuh-ocsf-${NODE}
usermod -aG wazuh wazuh-ocsf-${NODE}
chown -R wazuh-ocsf-${NODE}: /opt/wazuh-ocsf-${NODE}
```

### Per-node `.env`

All instances point to the **same** ClickHouse. Only `STATE_FILE` differs (keeps the byte-offset local to the node's own `alerts.json`):

```dotenv
# /opt/wazuh-ocsf-wazuh-master/.env
CLICKHOUSE_URL=http://clickhouse.internal:8123
CLICKHOUSE_DATABASE=wazuh_ocsf
CLICKHOUSE_USER=wazuh_etl
CLICKHOUSE_PASSWORD=strongpassword
ALERTS_FILE=/var/ossec/logs/alerts/alerts.json
STATE_FILE=/opt/wazuh-ocsf-wazuh-master/state/alerts.pos
DATA_TTL_DAYS=180
```

> `STATE_FILE` **must** stay on the local node — it tracks the byte offset into that node's own `alerts.json` and has no meaning on any other node.

### Per-node systemd unit

Create `/etc/systemd/system/wazuh-ocsf-etl-wazuh-master.service` (adjust name per node):

```ini
[Unit]
Description=Wazuh → OCSF → ClickHouse ETL (wazuh-master)
After=network.target wazuh-manager.service

[Service]
Type=simple
User=wazuh-ocsf-wazuh-master
Group=wazuh-ocsf-wazuh-master
WorkingDirectory=/opt/wazuh-ocsf-wazuh-master
EnvironmentFile=/opt/wazuh-ocsf-wazuh-master/.env
ExecStart=/usr/local/bin/wazuh-ocsf-etl
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30
LimitNOFILE=65536
MemoryMax=512M
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/opt/wazuh-ocsf-wazuh-master/state
ReadOnlyPaths=/var/ossec/logs/alerts /opt/wazuh-ocsf-wazuh-master/config
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now wazuh-ocsf-etl-wazuh-master
```

### Distinguishing data from different nodes

Every Wazuh alert JSON contains `"manager": {"name": "<hostname>"}`. This is stored in the `manager_name` column in every ClickHouse row — automatically, no configuration needed.

```sql
-- Which nodes are actively sending data?
SELECT manager_name, count() AS events, max(time) AS last_seen
FROM wazuh_ocsf.ocsf_my_agent
WHERE time >= now() - INTERVAL 1 HOUR
GROUP BY manager_name
ORDER BY events DESC;

-- Authentication failures across ALL nodes over last 24 h
SELECT time, manager_name, device_name, actor_user, src_ip, severity
FROM wazuh_ocsf.ocsf_my_agent
WHERE class_uid = 3002
  AND severity_id >= 3
  AND time >= now() - INTERVAL 1 DAY
ORDER BY time DESC
LIMIT 200;

-- Per-node event rate (EPS)
SELECT
    manager_name,
    toStartOfMinute(time) AS minute,
    count() / 60 AS eps
FROM wazuh_ocsf.ocsf_my_agent
WHERE time >= now() - INTERVAL 10 MINUTE
GROUP BY manager_name, minute
ORDER BY manager_name, minute;
```

### Concurrent inserts from multiple nodes into the same table

ClickHouse is designed for this. `CREATE TABLE IF NOT EXISTS` is idempotent — if two ETL instances race to create the same table on first start, ClickHouse creates it once and the second `IF NOT EXISTS` call silently succeeds. Concurrent `INSERT` statements from multiple nodes into the same table are fully supported and are the normal operating mode for distributed ingestion pipelines.

### ZeroMQ in cluster mode

Each Wazuh node's `wazuh-analysisd` has its own ZeroMQ PUB socket. Deploy one ETL per node pointing to `tcp://localhost:11111`. Do **not** point multiple ETL instances at the same socket — each message is fanned out to every subscriber independently, so each instance would receive 100% of messages from only that one node.

```dotenv
# Each node's .env in ZeroMQ mode — always localhost
INPUT_MODE=zeromq
ZEROMQ_URI=tcp://localhost:11111
```

### Summary: single-node vs. cluster

| | Single-node | Cluster |
|---|---|---|
| ETL instances | 1 | 1 per Wazuh node (master + each worker) |
| `ALERTS_FILE` | `/var/ossec/logs/alerts/alerts.json` | Same — each reads its local copy |
| `STATE_FILE` | Any path | **Must be different per node** |
| ClickHouse target | One DB | **Same DB, same tables** |
| Node identification | — | `manager_name` column populated automatically |
| Code changes needed | — | **None** — same binary, different config |

---

## 18. OCSF schema validation

After every successful `transform()` call the pipeline runs a lightweight OCSF 1.7.0 schema validator against the produced record. This catches mapping bugs and schema drift early — before bad data reaches ClickHouse.

### Design principles

- **Warn-only — never drops events.** Every event is always forwarded to ClickHouse regardless of validation outcome. The validator is a diagnostic tool, not a gate.
- **Zero cost on the happy path.** The internal violation list starts at capacity-0 (`Vec::new()`). No heap allocation is performed unless a violation is actually found.
- **O(1) checks only.** All validation is constant-time comparisons against compile-time slices — no regex, no I/O, no locking.
- **Toggled at runtime.** Set `OCSF_VALIDATE=false` in `.env` to disable entirely (useful during load testing or benchmarking).

### What is checked

| Check | What it catches |
|---|---|
| `class_uid` is a recognised OCSF 1.7.0 class | Rogue class IDs if `classify_event()` produces an unknown value |
| `severity_id` is in `{0, 1, 2, 3, 4, 5, 6, 99}` | Out-of-range values if Wazuh rule levels change unexpectedly |
| `type_uid == class_uid × 100 + activity_id` | The OCSF 1.7.0 type_uid derived-field formula — detects any class/activity mismatch |
| `activity_id` is valid for the class | e.g. activity_id 7 on a Network Activity record (which has no activity 7) |
| `category_uid` and `category_name` match the class | Prevents category drift when the classification table is edited |
| `time != 0` | `@timestamp` was missing or failed to parse — silent data quality issue |

### Startup log

```
INFO   ocsf_validate    : true (set OCSF_VALIDATE=false to disable)
```

### Violation log output

When a violation is found it is logged at `WARN` level with the full context:

```
WARN  OCSF schema violation(s) — event still recorded
      class_uid=2004 rule_id="100001"
      violations=["type_uid != class_uid * 100 + activity_id"]
```

All violations are also counted in an internal atomic counter. Query the total in `RUST_LOG=warn` output or grep the journal:

```bash
journalctl -u wazuh-ocsf-etl | grep "OCSF schema violation"
```

### Disabling for performance testing

```dotenv
# .env
OCSF_VALIDATE=false
```

At 10,000 EPS the validator adds roughly 0–1 µs per event (all hot-cache integer comparisons). Disabling it will not measurably change throughput in normal operation — it is provided for completeness.

---

## 19. Field standardisation: 1,200+ decoder fields → 29 OCSF columns

Wazuh ships with **171 decoder files** covering over 300 distinct log sources (Linux syslog, Windows Event Log, Cisco, Palo Alto, Fortinet, AWS, GCP, Okta, Zeek, Suricata, Docker, MS Graph, Office365, and many more). Together they produce over **1,200 unique field names** across all sources — no two vendors agree on naming.

This pipeline consolidates all field names to **29 typed OCSF ClickHouse columns** through the field resolver (`src/field_paths.rs`), which holds **567 source-name variants** (audited from all 171 decoder files and all 171 rule files) mapped to those 29 targets. Zero data is lost — vendor-opaque fields that have no OCSF equivalent are written to the `extensions` JSON column intact.

### Coverage summary

| Source diversity | After pipeline |
|---|---|
| 1,200+ unique Wazuh decoder field names | 29 typed OCSF columns |
| 171 decoder files + 171 rule files audited | Every record has the same schema |
| 567 source-field variants resolved | All remaining fields → `extensions` blob |
| ~47 % of decoder fields standardised | 100 % of data preserved |

### Consolidation ratio per column

The columns with the highest incoming-variant count — all collapsed to one standard name:

| OCSF column | Input variants → 1 | Example original field names |
|---|---|---|
| `src_ip` | 47 → 1 | `srcip`, `src_ip`, `IP`, `client`, `aws.sourceIPAddress`, `zeek.id.orig_h`, `okta.client.ipAddress`, `gcp.protoPayload.requestMetadata.callerIp`, `ClientIP`, `botnetip` |
| `actor_user` | 46 → 1 | `user`, `srcuser`, `username`, `audit.auid`, `aws.userIdentity.userName`, `okta.actor.alternateId`, `gcp.protoPayload.authenticationInfo.principalEmail`, `identity.user.name`, `win.eventdata.subjectAccountName` |
| `status` | 53 → 1 | `status`, `result`, `event.severity`, `reason`, `okta.outcome.result`, `audit.success`, `sca.check.result`, `virustotal.malicious`, `aws.finding.Compliance.Status`, `win.eventdata.errorCode`, `rcode`, `office365.ResultStatus` |
| `action` | 34 → 1 | `action`, `act`, `aws.eventName`, `gcp.protoPayload.methodName`, `azure.operationName`, `okta.eventType`, `office365.Operation`, `docker.Action`, `api.operation`, `operationName`, `audit.op`, `utmaction`, `WAFAction` |
| `dst_ip` | 20 → 1 | `dstip`, `dst_ip`, `aws.responseElements.ipAddress`, `zeek.id.resp_h`, `destinationIp` |
| `src_port` | 14 → 1 | `srcport`, `src_port`, `zeek.id.orig_p`, `data.sport` |
| `dst_port` | 14 → 1 | `dstport`, `dst_port`, `zeek.id.resp_p`, `data.dport` |
| `app_name` | 33 → 1 | `program`, `app`, `module`, `win.system.providerName`, `win.system.channel`, `metadata.product.name`, `mongodb.component`, `aws.finding.ProductName`, `ms-graph.detectionSource`, `office365.Workload`, `docker.Actor.Attributes.name` |
| `file_name` | 29 → 1 | `syscheck.path`, `sysmon.targetFilename`, `audit.file.name`, `object`, `win.eventdata.targetFileName`, `win.eventdata.imageLoaded`, `audit.directory.name`, `cylance_threats.file_path`, `infected_file_path` |
| `process_name` | 16 → 1 | `process.name`, `sysmon.image`, `audit.exe`, `win.eventdata.commandLine`, `win.eventdata.imagePath`, `audit.execve.a0`, `parameters.program` |
| `app_category` | 29 → 1 | `category`, `subtype`, `aws.type`, `aws.resourceType`, `sca.type`, `win.eventdata.logonType`, `event.type`, `event_type`, `subcategory`, `aws.userIdentity.type`, `office365.InternalLogonType`, `office365.LogonType` |
| `rule_name` | 16 → 1 | `rule_name`, `ThreatName`, `aws.title`, `aws.check-name`, `qualysguard.vulnerability_title`, `aws.finding.Compliance.SecurityControlId`, `threat.software.id`, `virus`, `defender.name` |

### Verified against OCSF 1.7.0

All remaining fields left in `extensions` were checked against the complete OCSF 1.7.0 attribute dictionary across all 31 classes and `base_event`. None of them have an equivalent typed OCSF column — they are legitimately vendor-opaque identifiers, internal codes, and platform-specific metrics. Storing them in `extensions` is correct per the OCSF extensibility model ( "Profiles & Extensions").

The 567 path variants were derived by auditing:
- All **171 Wazuh decoder XML files** (`<order>` tag fields from `/var/ossec/ruleset/decoders/`)
- All **171 Wazuh rule XML files** (`<field name="...">` conditions from `/var/ossec/ruleset/rules/`)
- Cloud vendor SDK docs for AWS, GCP, Azure, Office365, MS Graph, Okta, Zeek, and Suricata
- Cloudflare WAF, Docker event log, Amazon Security Lake OCSF-native relay fields

### OCSF 1.7.0 compliance audit — 7 field corrections

All 29 extraction arrays were audited against the OCSF 1.7.0 attribute dictionary. Seven fields were found in semantically-incorrect arrays and were relocated:

| Field | Was in | Moved to | OCSF rationale |
|---|---|---|---|
| `api.operation` | `HTTP_METHOD` | `ACTION` | `http_method` accepts HTTP verbs only (GET/POST/…). Operation names are `activity_name`-equivalent → `action`. |
| `operationName` | `HTTP_METHOD` | `ACTION` | Same — Azure/generic operation names are not HTTP verbs. |
| `aws.userIdentity.type` | `APP_NAME` | `CATEGORY` | Represents OCSF `actor.user.type` (IAMUser/AssumedRole/AWSService) — an identity classification, not a product name. |
| `virus` | `FILE_NAME` | `RULE_NAME` | ClamAV virus names (e.g. `Eicar-Signature`) are `malware.name`-class identifiers, not file paths. |
| `defender.name` | `FILE_NAME` | `RULE_NAME` | Windows Defender threat names (e.g. `Trojan:Win32/Emotet`) are `malware.name`-class identifiers, not file paths. |
| `office365.InternalLogonType` | `STATUS` | `CATEGORY` | Logon type is an event classification integer, not an outcome/result string. |
| `office365.LogonType` | `STATUS` | `CATEGORY` | Same — grouped with the already-correct `win.eventdata.logonType` in `CATEGORY`. |

### Adding more mappings

Promote any field from `extensions` to a typed column either:
- **At runtime** via `config/field_mappings.toml` — hot-reloaded within 10 s, no restart. See [9](#9-custom-field-mappings).
- **At compile time** — add a source variant to the appropriate constant in `src/field_paths.rs` and rebuild.

Use the unmapped-field report ([11](#11-unmapped-field-discovery)) to identify the highest-frequency unmapped fields from live traffic before deciding which to promote.

---

## 20. Field mapping reference for Grafana dashboards

A comprehensive per-column and per-source mapping table is maintained in [`FIELD_MAPPINGS.md`](FIELD_MAPPINGS.md). It covers:

- Every typed ClickHouse column (name, type, OCSF path, source fields grouped by vendor)
- Per-source mapping tables for: Generic Wazuh, Windows Event Log, AWS (CloudTrail / VPC Flow / GuardDuty / more), Office365, GCP / Azure / Okta, Zeek / Suricata, and Vulnerability Detector
- Predefined `extensions` JSON keys (Windows, SCA, FIM, dpkg, AWS, and Office365 sub-fields)
- Sample Grafana SQL panel queries for the most common SOC dashboard panels

This is the recommended starting point for building any Grafana dashboard against the `wazuh_ocsf` database.
