# Architecture

## Project structure

The `src/` directory is organized into four modules:

```
src/
├── main.rs              # entry point, async runtime setup
├── input/               # data ingestion
│   ├── tailer.rs        # tails JSON alert files
│   ├── state.rs         # file-position bookkeeping
│   └── zmq.rs           # ZeroMQ subscriber
├── pipeline/            # ETL core
│   ├── classify.rs      # rule/decoder → OCSF class + category
│   ├── transform.rs     # Wazuh alert → OCSF record
│   ├── record.rs        # OCSF record type definitions
│   ├── validator.rs     # optional OCSF schema validation
│   └── field_paths.rs   # source-field path constants
├── output/              # data sinks
│   └── db.rs            # ClickHouse HTTP writer + table management
└── util/                # shared helpers
    ├── json.rs          # JSON extraction utilities
    └── unmapped.rs      # unmapped-field collection
```

## Pipeline model

The service has two main async stages:

1. Reader (`src/input/`)
- `tailer.rs` tails a JSON alert file, or `zmq.rs` subscribes to a ZeroMQ socket
- `state.rs` tracks the last-read file position for resumption
- sends alerts through a bounded channel

2. Processor/Writer (`src/pipeline/` + `src/output/`)
- `classify.rs` infers OCSF class and category from rule/decoder context
- `transform.rs` converts the Wazuh alert into an OCSF record (`record.rs`)
- `validator.rs` optionally validates the record against the OCSF schema
- `field_paths.rs` defines the source-field path constants used during mapping
- `db.rs` batches rows by destination table and flushes to ClickHouse via HTTP

Helper code in `src/util/` (`json.rs`, `unmapped.rs`) is shared across stages.

## Table strategy

Tables are auto-created in ClickHouse as data appears:

- Per-agent: `ocsf_<agent_name>`
- Shared-source routing via `SPECIAL_LOCATIONS`

## OCSF mapping

- Class and category are inferred from rule/decoder context (`src/pipeline/classify.rs`)
- Common source fields are normalized into typed OCSF columns (`src/pipeline/transform.rs`)
- Unmatched vendor fields are retained in `extensions` (`src/util/unmapped.rs`)

## Validation

Optional OCSF validation checks run after transform (`src/pipeline/validator.rs`).

- Warn-only behavior
- Events are still written to ClickHouse

## Deep reference

- Full field mapping matrix: [../FIELD_MAPPINGS.md](../FIELD_MAPPINGS.md)
- Full legacy technical reference: [reference-full.md](reference-full.md)
