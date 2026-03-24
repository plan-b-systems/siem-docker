#!/usr/bin/env bash
# ============================================================
# Plan-B Systems SIEM Stack – Installer
# ============================================================
# Usage:
#   1. cp config.env.template config.env
#   2. nano config.env          (fill in all values)
#   3. sudo ./install.sh
# ============================================================
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
step()    { echo -e "\n${BLUE}${BOLD}══ $* ${NC}"; }
die()     { error "$*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║       Plan-B Systems SIEM Stack – Installer          ║"
echo "║       Graylog 7.2 + OpenSearch 2.x + MongoDB 7.0    ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ════════════════════════════════════════════════════════════
# 0. Root check
# ════════════════════════════════════════════════════════════
[[ $EUID -ne 0 ]] && die "This script must be run as root (use sudo)"

# ════════════════════════════════════════════════════════════
# 1. config.env gate
# ════════════════════════════════════════════════════════════
step "Checking configuration"

if [[ ! -f config.env ]]; then
    warn "config.env not found."
    info "Creating from template …"
    cp config.env.template config.env
    echo ""
    echo -e "${YELLOW}  Please edit config.env and fill in all values, then re-run install.sh${NC}"
    echo "  nano config.env"
    exit 0
fi

# shellcheck disable=SC1091
set -a; source config.env; set +a
info "config.env loaded"

# Validate mandatory fields
REQUIRED_VARS=(CLIENT_NAME CLIENT_ID GRAYLOG_HOSTNAME GRAYLOG_ADMIN_PASSWORD TIMEZONE)
for var in "${REQUIRED_VARS[@]}"; do
    [[ -z "${!var:-}" ]] && die "config.env: ${var} is not set"
done
info "Mandatory variables present"

# ════════════════════════════════════════════════════════════
# 2. Prerequisite checks
# ════════════════════════════════════════════════════════════
step "Checking prerequisites"

# Docker
if ! command -v docker &>/dev/null; then
    die "Docker is not installed. Install with: curl -fsSL https://get.docker.com | sh"
fi
DOCKER_VER=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "0.0.0")
DOCKER_MAJ=$(echo "$DOCKER_VER" | cut -d. -f1)
[[ $DOCKER_MAJ -lt 24 ]] && die "Docker >= 24.0 required (found ${DOCKER_VER})"
info "Docker ${DOCKER_VER} OK"

# Docker Compose (v2 plugin)
if ! docker compose version &>/dev/null; then
    die "Docker Compose v2 plugin not found. Install: apt-get install docker-compose-plugin"
fi
COMPOSE_VER=$(docker compose version --short 2>/dev/null || echo "0.0.0")
info "Docker Compose ${COMPOSE_VER} OK"

# openssl
command -v openssl &>/dev/null || die "openssl not installed: apt-get install openssl"
info "openssl OK"

# envsubst (gettext package)
command -v envsubst &>/dev/null || die "envsubst not found: apt-get install gettext-base"
info "envsubst OK"

# RAM
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_GB=$(( TOTAL_RAM_KB / 1024 / 1024 ))
[[ $TOTAL_RAM_GB -lt 7 ]] && warn "Recommended RAM >= 8 GB (found ${TOTAL_RAM_GB} GB)"
info "RAM: ${TOTAL_RAM_GB} GB"

# Disk space (require 50 GB free on the install partition)
FREE_GB=$(df -BG "$SCRIPT_DIR" | awk 'NR==2{gsub(/G/,"",$4); print $4}')
[[ $FREE_GB -lt 50 ]] && warn "Recommended free disk >= 50 GB (found ${FREE_GB} GB free)"
info "Free disk: ${FREE_GB} GB"

# ════════════════════════════════════════════════════════════
# 3. Generate secrets (idempotent – skip if already present)
# ════════════════════════════════════════════════════════════
step "Generating secrets"

SECRETS_CHANGED=false

# GRAYLOG_PASSWORD_SECRET (min 96 random chars)
if ! grep -q "^GRAYLOG_PASSWORD_SECRET=" config.env 2>/dev/null || \
   [[ -z "$(grep "^GRAYLOG_PASSWORD_SECRET=" config.env | cut -d= -f2-)" ]]; then
    PW_SECRET=$(openssl rand -base64 72 | tr -dc 'a-zA-Z0-9' | head -c 96)
    # Remove placeholder line if present, then append real value
    sed -i '/^#\s*GRAYLOG_PASSWORD_SECRET=/d' config.env
    sed -i '/^GRAYLOG_PASSWORD_SECRET=/d' config.env
    echo "GRAYLOG_PASSWORD_SECRET=${PW_SECRET}" >> config.env
    info "Generated GRAYLOG_PASSWORD_SECRET"
    SECRETS_CHANGED=true
else
    info "GRAYLOG_PASSWORD_SECRET already set – skipping"
fi

# GRAYLOG_ROOT_PASSWORD_SHA2 (SHA-256 of admin password)
ROOT_SHA2=$(echo -n "${GRAYLOG_ADMIN_PASSWORD}" | sha256sum | awk '{print $1}')
sed -i '/^#\s*GRAYLOG_ROOT_PASSWORD_SHA2=/d' config.env
sed -i '/^GRAYLOG_ROOT_PASSWORD_SHA2=/d' config.env
echo "GRAYLOG_ROOT_PASSWORD_SHA2=${ROOT_SHA2}" >> config.env
info "Generated GRAYLOG_ROOT_PASSWORD_SHA2"

# Reload after appending
set -a; source config.env; set +a

# ════════════════════════════════════════════════════════════
# 4. TLS certificates
# ════════════════════════════════════════════════════════════
step "TLS certificates"

if [[ -f certs/graylog.crt && -f certs/graylog.key ]]; then
    info "Certificates already exist – skipping generation"
    info "  To regenerate: rm certs/graylog.{crt,key,csr} && ./install.sh"
else
    info "Generating self-signed TLS certificate …"
    chmod +x certs/generate-certs.sh
    bash certs/generate-certs.sh config.env
fi

chmod 600 certs/ca.key 2>/dev/null || true       # CA key stays private
chmod 644 certs/graylog.key 2>/dev/null || true  # server key readable by Graylog container (uid 1100)

# ════════════════════════════════════════════════════════════
# 5. Render Graylog config from template
# ════════════════════════════════════════════════════════════
step "Rendering Graylog configuration"

envsubst < graylog/graylog.conf.template > graylog/graylog.conf
chmod 640 graylog/graylog.conf
info "graylog/graylog.conf written"

# ════════════════════════════════════════════════════════════
# 6. Host OS tuning (required for OpenSearch)
# ════════════════════════════════════════════════════════════
step "Host OS tuning"

# vm.max_map_count – required by OpenSearch / Elasticsearch
CURRENT_MAP=$(sysctl -n vm.max_map_count)
if [[ $CURRENT_MAP -lt 262144 ]]; then
    sysctl -w vm.max_map_count=262144
    info "Set vm.max_map_count=262144 (runtime)"
fi

SYSCTL_CONF="/etc/sysctl.d/99-plansb-siem.conf"
if [[ ! -f "$SYSCTL_CONF" ]] || ! grep -q "vm.max_map_count" "$SYSCTL_CONF"; then
    cat > "$SYSCTL_CONF" <<'EOF'
# Plan-B Systems SIEM – required for OpenSearch
vm.max_map_count=262144
# Increase UDP receive buffer for syslog ingestion
net.core.rmem_max=26214400
net.core.rmem_default=262144
EOF
    info "Written ${SYSCTL_CONF}"
fi

# Limits for OpenSearch – /etc/security/limits.d
LIMITS_CONF="/etc/security/limits.d/99-plansb-opensearch.conf"
if [[ ! -f "$LIMITS_CONF" ]]; then
    cat > "$LIMITS_CONF" <<'EOF'
# Plan-B Systems SIEM – OpenSearch ulimits
*    soft  nofile  65536
*    hard  nofile  65536
*    soft  memlock unlimited
*    hard  memlock unlimited
EOF
    info "Written ${LIMITS_CONF}"
fi

# ════════════════════════════════════════════════════════════
# 7. Build license-checker image
# ════════════════════════════════════════════════════════════
step "Building license-checker image"

docker compose --env-file config.env build license-checker
info "license-checker image built"

# ════════════════════════════════════════════════════════════
# 8. Pull upstream images
# ════════════════════════════════════════════════════════════
step "Pulling Docker images"

docker compose --env-file config.env pull mongodb opensearch graylog
info "Images pulled"

# ════════════════════════════════════════════════════════════
# 9. Start core services (without license-checker first)
# ════════════════════════════════════════════════════════════
step "Starting SIEM services"

docker compose --env-file config.env up -d mongodb opensearch
info "MongoDB and OpenSearch starting …"

# Wait for OpenSearch health
info "Waiting for OpenSearch to become healthy (up to 3 minutes) …"
TIMEOUT=180
ELAPSED=0
until docker compose --env-file config.env exec -T opensearch \
      curl -sf http://localhost:9200/_cluster/health &>/dev/null; do
    sleep 5; ELAPSED=$((ELAPSED+5))
    [[ $ELAPSED -ge $TIMEOUT ]] && die "OpenSearch failed to start within ${TIMEOUT}s"
    echo -n "."
done
echo ""
info "OpenSearch is healthy"

# Start Graylog
docker compose --env-file config.env up -d graylog
info "Graylog starting …"

info "Waiting for Graylog to become healthy (up to 5 minutes) …"
TIMEOUT=300
ELAPSED=0
until curl -sk https://localhost:${GRAYLOG_WEB_PORT:-9000}/api/ \
      -o /dev/null -w "%{http_code}" 2>/dev/null | grep -q "200\|401"; do
    sleep 10; ELAPSED=$((ELAPSED+10))
    [[ $ELAPSED -ge $TIMEOUT ]] && die "Graylog failed to start within ${TIMEOUT}s"
    echo -n "."
done
echo ""
info "Graylog is healthy"

# ════════════════════════════════════════════════════════════
# 10. Configure Graylog via REST API
# ════════════════════════════════════════════════════════════
step "Configuring Graylog inputs"

GL_API="https://localhost:${GRAYLOG_WEB_PORT:-9000}/api"
GL_AUTH="admin:${GRAYLOG_ADMIN_PASSWORD}"

# Helper: POST to Graylog API (ignores duplicate errors)
gl_post() {
    local endpoint="$1"; shift
    local body="$1"
    local http_code
    http_code=$(curl -sk -o /tmp/gl_resp.json -w "%{http_code}" \
        -u "$GL_AUTH" \
        -H "Content-Type: application/json" \
        -H "X-Requested-By: install.sh" \
        -d "$body" \
        "${GL_API}${endpoint}")
    if [[ "$http_code" =~ ^(200|201|400)$ ]]; then
        # 400 usually means "already exists" in Graylog
        return 0
    fi
    warn "API call to ${endpoint} returned HTTP ${http_code}"
    cat /tmp/gl_resp.json 2>/dev/null || true
    return 1
}

# ── Syslog UDP input ─────────────────────────────────────────
info "Creating Syslog UDP input (port ${SYSLOG_UDP_PORT:-514}) …"
gl_post "/system/inputs" '{
  "title":  "Syslog UDP",
  "type":   "org.graylog2.inputs.syslog.udp.SyslogUDPInput",
  "global": true,
  "configuration": {
    "bind_address":        "0.0.0.0",
    "port":                '"${SYSLOG_UDP_PORT:-514}"',
    "recv_buffer_size":    262144,
    "number_worker_threads": 2,
    "override_source":     null,
    "force_rdns":          false,
    "allow_override_date": true,
    "expand_structured_data": false,
    "store_full_message":  true
  }
}' && info "Syslog UDP input OK"

# ── Syslog TCP input ─────────────────────────────────────────
info "Creating Syslog TCP input (port ${SYSLOG_TCP_PORT:-1514}) …"
gl_post "/system/inputs" '{
  "title":  "Syslog TCP",
  "type":   "org.graylog2.inputs.syslog.tcp.SyslogTCPInput",
  "global": true,
  "configuration": {
    "bind_address":          "0.0.0.0",
    "port":                  '"${SYSLOG_TCP_PORT:-1514}"',
    "recv_buffer_size":      1048576,
    "number_worker_threads": 2,
    "override_source":       null,
    "force_rdns":            false,
    "allow_override_date":   true,
    "expand_structured_data": false,
    "store_full_message":    true,
    "max_message_size":      2097152,
    "tls_enable":            false
  }
}' && info "Syslog TCP input OK"

# ── GELF UDP input ───────────────────────────────────────────
info "Creating GELF UDP input (port ${GELF_UDP_PORT:-12201}) …"
gl_post "/system/inputs" '{
  "title":  "GELF UDP",
  "type":   "org.graylog2.inputs.gelf.udp.GELFUDPInput",
  "global": true,
  "configuration": {
    "bind_address":          "0.0.0.0",
    "port":                  '"${GELF_UDP_PORT:-12201}"',
    "recv_buffer_size":      262144,
    "number_worker_threads": 2,
    "decompress_size_limit": 8388608
  }
}' && info "GELF UDP input OK"

# ── GELF TCP input ───────────────────────────────────────────
info "Creating GELF TCP input (port ${GELF_TCP_PORT:-12202}) …"
gl_post "/system/inputs" '{
  "title":  "GELF TCP",
  "type":   "org.graylog2.inputs.gelf.tcp.GELFTCPInput",
  "global": true,
  "configuration": {
    "bind_address":          "0.0.0.0",
    "port":                  '"${GELF_TCP_PORT:-12202}"',
    "recv_buffer_size":      1048576,
    "number_worker_threads": 2,
    "max_message_size":      2097152,
    "tls_enable":            false,
    "tcp_keepalive":         true
  }
}' && info "GELF TCP input OK"

# ── Index set – retention & log integrity ────────────────────
info "Configuring default index set retention (${RETENTION_DAYS:-365} days) …"
# Get default index set ID
DEFAULT_INDEX_SET_ID=$(curl -sk -u "$GL_AUTH" \
    -H "X-Requested-By: install.sh" \
    "${GL_API}/system/indices/index_sets?stats=false" \
    | python3 -c "import sys,json; sets=json.load(sys.stdin)['index_sets']; \
      print(next(s['id'] for s in sets if s.get('default',False)))" 2>/dev/null || echo "")

if [[ -n "$DEFAULT_INDEX_SET_ID" ]]; then
    curl -sk -o /dev/null -X PUT \
        -u "$GL_AUTH" \
        -H "Content-Type: application/json" \
        -H "X-Requested-By: install.sh" \
        -d '{
          "title":                   "Default index set",
          "description":             "Plan-B SIEM – '"${CLIENT_NAME}"'",
          "index_prefix":            "graylog",
          "rotation_strategy_class": "org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategy",
          "rotation_strategy":       {"type":"org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategyConfig","rotation_period":"P1D"},
          "retention_strategy_class":"org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy",
          "retention_strategy":      {"type":"org.graylog2.indexer.retention.strategies.DeletionRetentionStrategyConfig","max_number_of_indices":'"${RETENTION_DAYS:-365}"'},
          "creation_date":           "'"$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"'",
          "index_analyzer":          "standard",
          "shards":                  1,
          "replicas":                0,
          "index_optimization_max_num_segments": 1,
          "index_optimization_disabled": false,
          "writable":                true,
          "default":                 true
        }' \
        "${GL_API}/system/indices/index_sets/${DEFAULT_INDEX_SET_ID}" && \
    info "Index set retention set to ${RETENTION_DAYS:-365} indices (days)"
else
    warn "Could not retrieve default index set ID – retention must be set manually"
fi

# ════════════════════════════════════════════════════════════
# 11. Start license checker
# ════════════════════════════════════════════════════════════
step "Starting license checker"

docker compose --env-file config.env up -d license-checker
info "License checker started"

# ════════════════════════════════════════════════════════════
# 12. Configure systemd auto-start on boot
# ════════════════════════════════════════════════════════════
step "Configuring systemd service"

UNIT_FILE="/etc/systemd/system/plansb-siem.service"
cat > "$UNIT_FILE" <<UNIT
[Unit]
Description=Plan-B Systems SIEM Stack
After=docker.service network-online.target
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${SCRIPT_DIR}
ExecStart=/usr/bin/docker compose --env-file config.env up -d
ExecStop=/usr/bin/docker compose --env-file config.env down
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable plansb-siem.service
info "systemd service enabled (plansb-siem.service)"

# ════════════════════════════════════════════════════════════
# Done
# ════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║              Installation complete!                  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  Graylog UI  : ${BOLD}https://${GRAYLOG_HOSTNAME}:${GRAYLOG_WEB_PORT:-9000}${NC}"
echo -e "  Username    : ${BOLD}admin${NC}"
echo -e "  Password    : ${BOLD}${GRAYLOG_ADMIN_PASSWORD}${NC}"
echo ""
echo -e "  CA cert for browser : ${BOLD}${SCRIPT_DIR}/certs/ca.crt${NC}"
echo ""
echo -e "  To check stack status : ${BOLD}docker compose --env-file config.env ps${NC}"
echo -e "  To view logs          : ${BOLD}docker compose --env-file config.env logs -f${NC}"
echo -e "  To reconfigure        : ${BOLD}sudo ./reconfigure.sh${NC}"
echo ""
