# wazuh-ocsf-etl

Production-grade Wazuh -> OCSF -> ClickHouse ETL pipeline in Rust.

This repository now uses a concise README and a docs-first structure.

## What this project does

- Reads Wazuh alerts from `alerts.json` (or ZeroMQ)
- Normalizes events to OCSF 1.7.0
- Writes batched records into ClickHouse
- Preserves ingest position (inode + offset) for restart safety
- Supports hot-reload field mappings for custom decoders

## How it works

```text
Wazuh manager
  -> alerts.json or ZeroMQ PUB
  -> wazuh-ocsf-etl (transform + classify + batch)
  -> ClickHouse
```

## Architecture (high level)

```text
Reader
  - file mode: tails alerts.json with inode+offset state
  - zeromq mode: subscribes to wazuh-analysisd PUB socket
        |
        v
Transformer
  - classify event to OCSF class/category
  - map fields to typed columns + extensions
        |
        v
Writer
  - batch by destination table
  - flush to ClickHouse over HTTP
  - auto-create DB/tables if needed
```

Delivery semantics:
- `file` mode: at-least-once with restart-safe resume via state file
- `zeromq` mode: at-most-once (lower latency, but no replay)

## Quick start

1. Clone and enter the repo

```bash
git clone https://github.com/yash22091/wazuh-ocsf-etl.git
cd wazuh-ocsf-etl
```

2. Build

```bash
cargo build --release
```

3. Install

```bash
sudo ./install.sh ./target/release/wazuh-ocsf-etl
```

4. Configure

Edit `/opt/wazuh-ocsf/.env` with your ClickHouse settings.

5. Start

```bash
systemctl start wazuh-ocsf-etl
journalctl -u wazuh-ocsf-etl -f
```

## Prerequisites

- Linux x86_64
- Rust 1.75+ (build time)
- ClickHouse 22.x+
- Wazuh manager 4.x with JSON output enabled

## Configuration basics

Primary runtime config lives in `.env` (commonly `/opt/wazuh-ocsf/.env`).

Most important keys:
- `INPUT_MODE` (`file` or `zeromq`)
- `CLICKHOUSE_URL`, `CLICKHOUSE_DATABASE`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`
- `ALERTS_FILE`, `STATE_FILE`, `SEEK_TO_END_ON_FIRST_RUN`
- `BATCH_SIZE`, `FLUSH_INTERVAL_SECS`, `CHANNEL_CAP`

Field mapping customization is done in `config/field_mappings.toml` and hot-reloads without restart.

## Documentation

- Project overview: [docs/overview.md](docs/overview.md)
- Installation and deployment: [docs/installation.md](docs/installation.md)
- Configuration (.env + field mappings): [docs/configuration.md](docs/configuration.md)
- ZeroMQ mode: [docs/zeromq.md](docs/zeromq.md)
- Operations and troubleshooting: [docs/operations.md](docs/operations.md)
- Architecture and OCSF mapping: [docs/architecture.md](docs/architecture.md)
- Wazuh cluster deployment: [docs/cluster.md](docs/cluster.md)
- Detailed field mapping reference: [FIELD_MAPPINGS.md](FIELD_MAPPINGS.md)
- Legacy full reference (old long README): [docs/reference-full.md](docs/reference-full.md)

## Completeness note

No technical detail was deleted during the split:
- Full original content is preserved in [docs/reference-full.md](docs/reference-full.md)
- The focused docs are reorganized views of that content by topic

## Why this layout

The old single-file README was too large for most readers.

Now:
- README gives the essentials quickly
- Deep details are split into focused docs
- You can jump directly to the page you need
