#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  wazuh-ocsf-etl  —  Installation Script
#
#  Usage:
#    sudo ./install.sh [OPTIONS] /path/to/wazuh-ocsf-etl
#
#  Options:
#    --run-as-root   Run the systemd service as root (solves alerts.json
#                    permission denied when Wazuh restricts group access)
#    --uninstall     Remove the binary, service unit, and system user
#    --help          Show this help message and exit
#
#  What this script does (8 steps):
#    1. Installs the binary to /usr/local/bin/
#    2. Creates a dedicated system user  wazuh-ocsf  (skipped with --run-as-root)
#    3. Creates /opt/wazuh-ocsf/{config,state}
#    4. Writes a default .env  (you must edit before starting)
#    5. Copies config/field_mappings.toml  (hot-reloaded every 10 s at runtime)
#    6. Sets file ownership/permissions
#    7. Writes /etc/systemd/system/wazuh-ocsf-etl.service
#    8. Runs systemctl daemon-reload + enable
#
#  Re-running this script on an existing installation is safe — it updates
#  the binary and service unit without overwriting .env or field_mappings.toml.
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
die()     { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }
header()  { echo -e "\n${BOLD}── $* ──${RESET}"; }

# ── Argument handling ─────────────────────────────────────────────────────────
RUN_AS_ROOT=false
ARGS=()
for arg in "$@"; do
    case "$arg" in
        --run-as-root) RUN_AS_ROOT=true ;;
        --help|-h)
            echo -e "${BOLD}wazuh-ocsf-etl install.sh${RESET}  —  Installer for the Wazuh → OCSF → ClickHouse pipeline"
            echo
            echo -e "${BOLD}USAGE${RESET}"
            echo "    sudo ./install.sh [OPTIONS] <path-to-binary>"
            echo
            echo -e "${BOLD}OPTIONS${RESET}"
            echo "    --run-as-root   Run the systemd service as root instead of creating a"
            echo "                    dedicated 'wazuh-ocsf' system user.  Use this when Wazuh"
            echo "                    restricts alerts.json to root only and you cannot add the"
            echo "                    service account to the 'wazuh' group (e.g. hardened builds)."
            echo
            echo "    --uninstall     Stop and disable the service, remove the binary and the"
            echo "                    systemd unit.  Does NOT delete /opt/wazuh-ocsf or the"
            echo "                    system user (to preserve state and config)."
            echo
            echo "    --help, -h      Show this help message and exit."
            echo
            echo -e "${BOLD}EXAMPLES${RESET}"
            echo "    # Standard install — service runs as dedicated 'wazuh-ocsf' user"
            echo "    sudo ./install.sh ./target/release/wazuh-ocsf-etl"
            echo
            echo "    # Install with root ownership — avoids alerts.json permission denied"
            echo "    sudo ./install.sh --run-as-root ./target/release/wazuh-ocsf-etl"
            echo
            echo "    # Upgrade binary on an existing installation (config is preserved)"
            echo "    cargo build --release"
            echo "    sudo ./install.sh ./target/release/wazuh-ocsf-etl"
            echo
            echo "    # Upgrade with root mode on an existing installation"
            echo "    sudo ./install.sh --run-as-root ./target/release/wazuh-ocsf-etl"
            echo
            echo "    # Uninstall"
            echo "    sudo ./install.sh --uninstall"
            echo
            echo -e "${BOLD}AFTER INSTALL${RESET}"
            echo "    1.  Edit config :  nano /opt/wazuh-ocsf/.env"
            echo "    2.  Start       :  systemctl start wazuh-ocsf-etl"
            echo "    3.  Watch logs  :  journalctl -u wazuh-ocsf-etl -f"
            echo "    4.  Status      :  systemctl status wazuh-ocsf-etl"
            echo
            echo -e "${BOLD}NOTES${RESET}"
            echo "    • Re-running the script on an existing install is safe."
            echo "      It replaces only the binary and service unit."
            echo "      Existing .env and field_mappings.toml are never overwritten."
            echo
            echo "    • The default (non-root) mode adds the 'wazuh-ocsf' user to the"
            echo "      'wazuh' group so it can read alerts.json.  If that still fails"
            echo "      (e.g. Wazuh uses mode 0600), re-run with --run-as-root."
            echo
            echo "    • Hot-reload: edit /opt/wazuh-ocsf/config/field_mappings.toml at"
            echo "      any time — the pipeline picks up changes within 10 seconds,"
            echo "      no restart required."
            echo
            echo -e "${BOLD}FILES INSTALLED${RESET}"
            echo "    /usr/local/bin/wazuh-ocsf-etl              binary"
            echo "    /opt/wazuh-ocsf/.env                       runtime config (edit this)"
            echo "    /opt/wazuh-ocsf/config/field_mappings.toml custom field mappings"
            echo "    /opt/wazuh-ocsf/state/                     runtime state (pos file, unmapped report)"
            echo "    /etc/systemd/system/wazuh-ocsf-etl.service systemd unit"
            echo
            exit 0
            ;;
        *) ARGS+=("$arg") ;;
    esac
done
set -- "${ARGS[@]+${ARGS[@]}}"

if [[ "${1:-}" == "--uninstall" ]]; then
    # ── Uninstall ──────────────────────────────────────────────────────────
    echo -e "${BOLD}Uninstalling wazuh-ocsf-etl…${RESET}"
    systemctl stop    wazuh-ocsf-etl 2>/dev/null && ok "Service stopped"      || true
    systemctl disable wazuh-ocsf-etl 2>/dev/null && ok "Service disabled"     || true
    rm -f  /etc/systemd/system/wazuh-ocsf-etl.service && ok "Service unit removed" || true
    systemctl daemon-reload
    rm -f  /usr/local/bin/wazuh-ocsf-etl          && ok "Binary removed"      || true
    echo
    warn "Data directory /opt/wazuh-ocsf has NOT been removed."
    warn "To remove it permanently:  rm -rf /opt/wazuh-ocsf"
    warn "To remove the service user: userdel wazuh-ocsf"
    echo
    ok "Uninstall complete."
    exit 0
fi

if [[ $# -lt 1 ]]; then
    echo -e "${BOLD}Usage:${RESET}  sudo $0 [--run-as-root] <path-to-wazuh-ocsf-etl-binary>"
    echo
    echo "  Examples:"
    echo "    sudo $0 ./target/release/wazuh-ocsf-etl"
    echo "    sudo $0 --run-as-root ./target/release/wazuh-ocsf-etl"
    echo
    echo "  More options:  sudo $0 --help"
    echo "  To uninstall:  sudo $0 --uninstall"
    exit 1
fi

BINARY_SRC="$1"

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    die "This script must be run as root.  Try: sudo $0 $*"
fi

# ── Validate binary ───────────────────────────────────────────────────────────
[[ -f "$BINARY_SRC" ]]       || die "Binary not found: $BINARY_SRC"
[[ -x "$BINARY_SRC" ]]       || chmod +x "$BINARY_SRC"
file "$BINARY_SRC" | grep -q "ELF" || \
    die "$BINARY_SRC does not look like an ELF binary (wrong file?)"

# ── Installer-local paths ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_MAPPINGS="${SCRIPT_DIR}/config/field_mappings.toml"

# ── Install paths ─────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/wazuh-ocsf"
BIN_DEST="/usr/local/bin/wazuh-ocsf-etl"
SERVICE_NAME="wazuh-ocsf-etl"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

if [[ "$RUN_AS_ROOT" == "true" ]]; then
    SERVICE_USER="root"
    SERVICE_GROUP="root"
    info "--run-as-root: service will run as root (bypasses alerts.json permission issues)"
else
    SERVICE_USER="wazuh-ocsf"
    SERVICE_GROUP="wazuh-ocsf"
fi

# ════════════════════════════════════════════════════════════════════════════
header "Step 1 — Install binary"
# ════════════════════════════════════════════════════════════════════════════

# Stop service before replacing binary (if running)
if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
    info "Stopping existing service before update…"
    systemctl stop "${SERVICE_NAME}"
fi

install -m 755 "$BINARY_SRC" "$BIN_DEST"
ok "Binary installed → $BIN_DEST"

BINARY_SIZE=$(du -sh "$BIN_DEST" | cut -f1)
info "Binary size: $BINARY_SIZE"

# ════════════════════════════════════════════════════════════════════════════
header "Step 2 — Create system user"
# ════════════════════════════════════════════════════════════════════════════

if [[ "$RUN_AS_ROOT" == "true" ]]; then
    ok "--run-as-root: skipping dedicated user creation (service will run as root)"
elif ! id -u "${SERVICE_USER}" &>/dev/null; then
    useradd \
        --system \
        --shell /sbin/nologin \
        --home-dir "${INSTALL_DIR}" \
        --comment "Wazuh OCSF ETL service account" \
        "${SERVICE_USER}"
    ok "System user '${SERVICE_USER}' created"
else
    ok "System user '${SERVICE_USER}' already exists — skipping"
fi

# ════════════════════════════════════════════════════════════════════════════
header "Step 3 — Create directory layout under /opt"
# ════════════════════════════════════════════════════════════════════════════

mkdir -p "${INSTALL_DIR}/config"
mkdir -p "${INSTALL_DIR}/state"
ok "Directories created: ${INSTALL_DIR}/{config,state}"

# ════════════════════════════════════════════════════════════════════════════
header "Step 4 — Write .env configuration"
# ════════════════════════════════════════════════════════════════════════════

ENV_FILE="${INSTALL_DIR}/.env"

if [[ -f "$ENV_FILE" ]]; then
    warn ".env already exists → skipping (edit manually: $ENV_FILE)"
else
    cat > "$ENV_FILE" <<'EOF'
# ══════════════════════════════════════════════════════════════════
#  wazuh-ocsf-etl  —  Runtime configuration
#  Edit this file, then run:  systemctl restart wazuh-ocsf-etl
# ══════════════════════════════════════════════════════════════════

# ── ClickHouse connection ─────────────────────────────────────────
CLICKHOUSE_URL=http://localhost:8123
CLICKHOUSE_DATABASE=wazuh_ocsf
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=

# ── Input source ──────────────────────────────────────────────────
# file   — read alerts.json from disk (default — works with any Wazuh install)
# zeromq — subscribe to wazuh-analysisd ZeroMQ PUB socket (no disk I/O)
#          REQUIRES Wazuh manager built from source with USE_ZEROMQ=yes
#          NOT available in default Wazuh binary packages (.deb/.rpm)
INPUT_MODE=file

# Path to Wazuh alerts JSON (FILE mode only)
ALERTS_FILE=/var/ossec/logs/alerts/alerts.json

# ZeroMQ URI (ZEROMQ mode only — see README for prerequisites)
# ZEROMQ_URI=tcp://localhost:11111

# ── State / config ────────────────────────────────────────────────
STATE_FILE=/opt/wazuh-ocsf/state/alerts.pos
UNMAPPED_FIELDS_FILE=/opt/wazuh-ocsf/state/unmapped_fields.json
FIELD_MAPPINGS_FILE=/opt/wazuh-ocsf/config/field_mappings.toml

# ── First-run behaviour ───────────────────────────────────────────
# true  = start from current end of file (skip historical data)
# false = process entire alerts.json from the beginning
SEEK_TO_END_ON_FIRST_RUN=true

# ── Throughput tuning ─────────────────────────────────────────────
BATCH_SIZE=5000
FLUSH_INTERVAL_SECS=5
CHANNEL_CAP=50000

# ── Data retention ────────────────────────────────────────────────
# Delete rows older than N days (leave empty to keep forever)
DATA_TTL_DAYS=90

# ── Raw data storage ──────────────────────────────────────────────
# true  = store the full raw Wazuh alert JSON in raw_data (default)
# false = write empty string — saves 40-70% table size, no data loss
STORE_RAW_DATA=true

# ── OCSF schema validation ────────────────────────────────────────
# Set false during load testing to skip per-event validation
OCSF_VALIDATE=true

# ── Logging ───────────────────────────────────────────────────────
# Levels: error | warn | info | debug | trace
RUST_LOG=info

# ── Special locations (optional) ─────────────────────────────────
# Comma-separated location names routed to shared tables instead
# of per-agent tables.  Example:
# SPECIAL_LOCATIONS=aws_cloudtrail,okta,azure_ad
EOF
    chmod 640 "$ENV_FILE"
    ok ".env created → $ENV_FILE"
    echo
    warn "╔══════════════════════════════════════════════════════════╗"
    warn "║  ACTION REQUIRED: edit .env before starting the service  ║"
    warn "║  ${ENV_FILE}                 ║"
    warn "╚══════════════════════════════════════════════════════════╝"
fi

# ════════════════════════════════════════════════════════════════════════════
header "Step 5 — Deploy field_mappings.toml"
# ════════════════════════════════════════════════════════════════════════════

MAPPINGS_DEST="${INSTALL_DIR}/config/field_mappings.toml"

if [[ -f "$LOCAL_MAPPINGS" ]]; then
    # Preserve existing customisations — only copy if destination is absent
    if [[ -f "$MAPPINGS_DEST" ]]; then
        warn "field_mappings.toml already exists → skipping (preserving your customisations)"
        info "To reset: cp ${LOCAL_MAPPINGS} ${MAPPINGS_DEST}"
    else
        cp "$LOCAL_MAPPINGS" "$MAPPINGS_DEST"
        ok "field_mappings.toml deployed → $MAPPINGS_DEST"
    fi
else
    # Script is running without the source tree — write a minimal default
    if [[ ! -f "$MAPPINGS_DEST" ]]; then
        cat > "$MAPPINGS_DEST" <<'EOF'
# ══════════════════════════════════════════════════════════════════
#  Wazuh → OCSF → ClickHouse  —  Custom Field Mappings
#  This file is hot-reloaded every 10 seconds.  No restart required.
# ══════════════════════════════════════════════════════════════════

[meta]
# OCSF schema version this deployment targets.
ocsf_version = "1.7.0"

# ── Custom decoder field mappings ─────────────────────────────────
# Map fields from your own decoders to OCSF columns.
#
# [field_mappings]
# "data.win.eventdata.ipAddress" = "src_ip"
# "data.srcip"                   = "src_ip"
# "data.dstip"                   = "dst_ip"
EOF
        ok "Minimal field_mappings.toml written → $MAPPINGS_DEST"
    else
        ok "field_mappings.toml already exists — skipping"
    fi
fi

# ════════════════════════════════════════════════════════════════════════════
header "Step 6 — Set file permissions"
# ════════════════════════════════════════════════════════════════════════════

chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${INSTALL_DIR}"
chmod 750 "${INSTALL_DIR}"
chmod 750 "${INSTALL_DIR}/config"
chmod 750 "${INSTALL_DIR}/state"
chmod 640 "${INSTALL_DIR}/config/field_mappings.toml"
ok "Ownership: ${SERVICE_USER}:${SERVICE_GROUP} → ${INSTALL_DIR}"

if [[ "$RUN_AS_ROOT" == "true" ]]; then
    ok "--run-as-root: alerts.json will be readable by root — no group membership needed"
else
    # Add wazuh-ocsf to the wazuh group so it can read alerts.json
    if getent group wazuh &>/dev/null; then
        usermod -aG wazuh "${SERVICE_USER}"
        ok "Added '${SERVICE_USER}' to the 'wazuh' group (alerts.json access)"
    else
        warn "'wazuh' group not found — if Wazuh is on this host, run:"
        warn "    usermod -aG wazuh ${SERVICE_USER}"
        warn "Or re-install with --run-as-root to bypass this entirely."
    fi
fi

# ════════════════════════════════════════════════════════════════════════════
header "Step 7 — Install systemd service unit"
# ════════════════════════════════════════════════════════════════════════════

# Build the security hardening block — relaxed for root mode since
# ProtectSystem=strict + NoNewPrivileges would be redundant for root,
# and ReadOnlyPaths restrictions are unnecessary when running as root.
if [[ "$RUN_AS_ROOT" == "true" ]]; then
    HARDENING_BLOCK="# Running as root — file-system restrictions omitted."
else
    HARDENING_BLOCK="# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=${INSTALL_DIR}/state
ReadOnlyPaths=/var/ossec/logs/alerts ${INSTALL_DIR}/config
PrivateTmp=yes"
fi

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Wazuh → OCSF → ClickHouse ETL pipeline
Documentation=https://github.com/mranv/wazuh-ocsf-etl
After=network.target
# Uncomment if ClickHouse runs on the same host:
# After=network.target clickhouse-server.service

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${BIN_DEST}
Restart=on-failure
RestartSec=5s

# Allow time to flush in-flight data on stop
TimeoutStopSec=30

# Hard resource limits
LimitNOFILE=65536
MemoryMax=512M

${HARDENING_BLOCK}

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "$SERVICE_FILE"
ok "Service unit written → $SERVICE_FILE"

# ════════════════════════════════════════════════════════════════════════════
header "Step 8 — Reload systemd and enable service"
# ════════════════════════════════════════════════════════════════════════════

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
ok "Service enabled (starts on boot)"

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}══════════════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  Installation complete!${RESET}"
echo -e "${BOLD}══════════════════════════════════════════════════════════════${RESET}"
echo
echo -e "  Binary       : ${CYAN}${BIN_DEST}${RESET}"
echo -e "  Install dir  : ${CYAN}${INSTALL_DIR}${RESET}"
echo -e "  Config       : ${CYAN}${INSTALL_DIR}/.env${RESET}"
echo -e "  Field map    : ${CYAN}${INSTALL_DIR}/config/field_mappings.toml${RESET}"
echo -e "  State dir    : ${CYAN}${INSTALL_DIR}/state/${RESET}"
echo -e "  Service unit : ${CYAN}${SERVICE_FILE}${RESET}"
echo -e "  Service user : ${CYAN}${SERVICE_USER}${RESET}"
if [[ "$RUN_AS_ROOT" == "true" ]]; then
    echo -e "  Mode         : ${YELLOW}root (--run-as-root)${RESET}  — full alerts.json access, no group setup needed"
fi
echo
echo -e "${BOLD}Next steps:${RESET}"
echo -e "  1. Edit the configuration file:"
echo -e "       ${CYAN}nano ${INSTALL_DIR}/.env${RESET}"
echo
echo -e "  2. Start the service:"
echo -e "       ${CYAN}systemctl start ${SERVICE_NAME}${RESET}"
echo
echo -e "  3. Watch live logs:"
echo -e "       ${CYAN}journalctl -u ${SERVICE_NAME} -f${RESET}"
echo
echo -e "  4. Check service status:"
echo -e "       ${CYAN}systemctl status ${SERVICE_NAME}${RESET}"
echo
if [[ "$RUN_AS_ROOT" == "false" ]] && ! getent group wazuh &>/dev/null; then
    warn "'wazuh' group was not found on this host."
    warn "If alerts.json permission errors appear in the logs, either:"
    warn "  a) Run:  usermod -aG wazuh ${SERVICE_USER}  (then restart the service)"
    warn "  b) Re-install with:  sudo ./install.sh --run-as-root ${BIN_DEST}"
    echo
fi
echo -e "  To uninstall:  ${CYAN}sudo ./install.sh --uninstall${RESET}"
echo
