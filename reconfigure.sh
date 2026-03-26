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

REQUIRED_VARS=(CLIENT_NAME CLIENT_ID GRAYLOG_HOSTNAME GRAYLOG_ADMIN_PASSWORD
               TIMEZONE GRAYLOG_PASSWORD_SECRET GRAYLOG_ROOT_PASSWORD_SHA2)
for var in "${REQUIRED_VARS[@]}"; do
    [[ -z "${!var:-}" ]] && die "config.env: ${var} is empty. Run install.sh first."
done

# ════════════════════════════════════════════════════════════
# 2. Regenerate SHA2 if admin password was changed
# ════════════════════════════════════════════════════════════
step "Checking admin password hash"

NEW_SHA2=$(echo -n "${GRAYLOG_ADMIN_PASSWORD}" | sha256sum | awk '{print $1}')
if [[ "$NEW_SHA2" != "${GRAYLOG_ROOT_PASSWORD_SHA2}" ]]; then
    info "Admin password changed – updating SHA2 hash"
    sed -i "s|^GRAYLOG_ROOT_PASSWORD_SHA2=.*|GRAYLOG_ROOT_PASSWORD_SHA2=${NEW_SHA2}|" config.env
    GRAYLOG_ROOT_PASSWORD_SHA2="$NEW_SHA2"
else
    info "Admin password unchanged"
fi

# ════════════════════════════════════════════════════════════
# 3. Regenerate TLS cert if hostname changed
# ════════════════════════════════════════════════════════════
step "Checking TLS certificate"

CERT_CN=""
if [[ -f certs/graylog.crt ]]; then
    CERT_CN=$(openssl x509 -in certs/graylog.crt -noout -subject 2>/dev/null \
              | sed -n 's/.*CN\s*=\s*\([^,/]*\).*/\1/p')
fi

if [[ "$CERT_CN" != "$GRAYLOG_HOSTNAME" ]]; then
    warn "Hostname changed (cert CN='${CERT_CN}', config='${GRAYLOG_HOSTNAME}')"
    info "Regenerating TLS certificate …"
    rm -f certs/graylog.{crt,key,csr}
    chmod +x certs/generate-certs.sh
    bash certs/generate-certs.sh config.env
    chmod 644 certs/graylog.key
    CERT_CHANGED=true
else
    info "TLS certificate hostname matches – no regeneration needed"
    CERT_CHANGED=false
fi

# ════════════════════════════════════════════════════════════
# 4. Re-render Graylog config
# ════════════════════════════════════════════════════════════
step "Rendering Graylog configuration"

envsubst < graylog/graylog.conf.template > graylog/graylog.conf
chmod 640 graylog/graylog.conf
info "graylog/graylog.conf updated"

# ════════════════════════════════════════════════════════════
# 5. Determine which services need restart
# ════════════════════════════════════════════════════════════
step "Applying changes"

# Always restart Graylog – config or env changes affect it
RESTART_GRAYLOG=true
RESTART_OPENSEARCH=false
RESTART_LICENSE=true

# OpenSearch heap change requires restart
# We compare running env vs config (best effort)
RUNNING_HEAP=$(docker inspect plansb-opensearch \
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

if [[ "$RESTART_GRAYLOG" == "true" ]]; then
    info "Restarting Graylog …"
    docker compose --env-file config.env up -d --force-recreate graylog

    info "Waiting for Graylog to become healthy …"
    TIMEOUT=300; ELAPSED=0
    until curl -sk "https://localhost:${GRAYLOG_WEB_PORT:-9000}/api/" \
          -o /dev/null -w "%{http_code}" 2>/dev/null | grep -q "200\|401"; do
        sleep 10; ELAPSED=$((ELAPSED+10))
        [[ $ELAPSED -ge $TIMEOUT ]] && die "Graylog failed to restart within ${TIMEOUT}s"
        echo -n "."
    done
    echo ""
    info "Graylog healthy"
fi

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
