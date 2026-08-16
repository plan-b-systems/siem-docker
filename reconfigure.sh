#!/usr/bin/env bash
# ============================================================
# Plan-B Systems SIEM Stack – Reconfiguration Script
# ============================================================
# Run this whenever config.env is edited to apply changes
# without a full reinstall.
#
# Usage:  sudo ./reconfigure.sh
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
step()  { echo -e "\n${BLUE}${BOLD}══ $* ${NC}"; }
die()   { error "$*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

[[ $EUID -ne 0 ]] && die "Run as root: sudo ./reconfigure.sh"

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║        Plan-B Systems SIEM – Reconfiguration         ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ════════════════════════════════════════════════════════════
# 1. Load and validate config
# ════════════════════════════════════════════════════════════
step "Loading configuration"

[[ ! -f config.env ]] && die "config.env not found. Run install.sh first."

# shellcheck disable=SC1091
set -a; source config.env; set +a
info "config.env loaded"

REQUIRED_VARS=(CLIENT_NAME CLIENT_ID TIMEZONE JWT_SECRET DASHBOARD_PASSWORD_HASH)
for var in "${REQUIRED_VARS[@]}"; do
    [[ -z "${!var:-}" ]] && die "config.env: ${var} is empty. Run install.sh first."
done

# NOTE: editing DASHBOARD_PASSWORD in config.env does NOT change the admin
# password. Since decision 15 (multi-user auth) the SQLite users.db is the
# source of truth; DASHBOARD_PASSWORD_HASH only seeds the admin on first boot.
# To reset the admin password use:  ./scripts/reset-admin.sh <new-password>
if [[ -n "${DASHBOARD_PASSWORD:-}" ]]; then
    warn "DASHBOARD_PASSWORD in config.env is only used to seed the first admin."
    warn "To change an existing admin password: ./scripts/reset-admin.sh <new-password>"
fi

# ════════════════════════════════════════════════════════════
# 2. Determine which services need restart
# ════════════════════════════════════════════════════════════
step "Applying changes"

# Dashboard and syslog-receiver read config.env at startup, so they always
# restart. OpenSearch only restarts when its heap changed — a restart there
# interrupts indexing.
RESTART_OPENSEARCH=false

RUNNING_HEAP=$(docker inspect plan-b-opensearch \
    --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
    | grep OPENSEARCH_JAVA_OPTS | grep -oP '\-Xmx\K[^ ]+' || echo "")
CONFIG_HEAP="${OPENSEARCH_HEAP_SIZE:-2g}"
if [[ "$RUNNING_HEAP" != "$CONFIG_HEAP" ]]; then
    info "OpenSearch heap changed ($RUNNING_HEAP → $CONFIG_HEAP) – will restart OpenSearch"
    RESTART_OPENSEARCH=true
fi

# ── Graceful restart sequence ────────────────────────────────

# Stop license-checker first to avoid false alarms during restart
info "Stopping license-checker …"
docker compose --env-file config.env stop license-checker 2>/dev/null || true

if [[ "$RESTART_OPENSEARCH" == "true" ]]; then
    warn "Restarting OpenSearch – indexing will be interrupted briefly"
    docker compose --env-file config.env up -d --force-recreate opensearch

    TIMEOUT=180; ELAPSED=0
    until docker compose --env-file config.env exec -T opensearch \
          curl -sf http://localhost:9200/_cluster/health &>/dev/null; do
        sleep 5; ELAPSED=$((ELAPSED+5))
        [[ $ELAPSED -ge $TIMEOUT ]] && die "OpenSearch failed to restart"
        echo -n "."
    done
    echo ""
    info "OpenSearch healthy"
fi

info "Restarting syslog-receiver …"
docker compose --env-file config.env up -d --force-recreate syslog-receiver

info "Restarting dashboard …"
docker compose --env-file config.env up -d --force-recreate dashboard

info "Waiting for dashboard to become healthy …"
TIMEOUT=120; ELAPSED=0
until docker compose --env-file config.env exec -T dashboard \
      node -e "fetch('http://localhost:3000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" &>/dev/null; do
    sleep 5; ELAPSED=$((ELAPSED+5))
    [[ $ELAPSED -ge $TIMEOUT ]] && die "Dashboard failed to restart within ${TIMEOUT}s"
    echo -n "."
done
echo ""
info "Dashboard healthy"

# Restart license-checker
info "Restarting license-checker …"
docker compose --env-file config.env up -d --force-recreate license-checker

# ════════════════════════════════════════════════════════════
# Done
# ════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}${BOLD}Reconfiguration complete.${NC}"
echo ""
echo -e "  Stack status : ${BOLD}docker compose --env-file config.env ps${NC}"
echo ""
