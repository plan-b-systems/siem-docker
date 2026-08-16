#!/usr/bin/env bash
# ============================================================
# Plan-B Systems SIEM v2 – Installer
# ============================================================
# No Graylog, no MongoDB — just OpenSearch + Syslog + Dashboard
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

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║       Plan-B Systems SIEM v2 – Installer             ║"
echo "║       OpenSearch 2.x + Syslog + Dashboard            ║"
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
    echo -e "${YELLOW}  Please edit config.env, then re-run install.sh${NC}"
    exit 0
fi

set -a; source config.env; set +a
info "config.env loaded"

REQUIRED_VARS=(CLIENT_NAME CLIENT_ID HOST_IP DASHBOARD_PASSWORD TIMEZONE)
for var in "${REQUIRED_VARS[@]}"; do
    [[ -z "${!var:-}" ]] && die "config.env: ${var} is not set"
done
info "Mandatory variables present"

# ════════════════════════════════════════════════════════════
# 2. Prerequisites
# ════════════════════════════════════════════════════════════
step "Checking prerequisites"

command -v docker &>/dev/null || die "Docker not installed: curl -fsSL https://get.docker.com | sh"
docker compose version &>/dev/null || die "Docker Compose v2 not found"
command -v openssl &>/dev/null || die "openssl not installed"
info "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null) OK"

TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_GB=$(( TOTAL_RAM_KB / 1024 / 1024 ))
[[ $TOTAL_RAM_GB -lt 3 ]] && warn "Recommended RAM >= 4 GB (found ${TOTAL_RAM_GB} GB)"
info "RAM: ${TOTAL_RAM_GB} GB"

# ════════════════════════════════════════════════════════════
# 3. Generate secrets
# ════════════════════════════════════════════════════════════
step "Generating secrets"

# JWT_SECRET
if ! grep -q "^JWT_SECRET=" config.env 2>/dev/null || \
   [[ -z "$(grep "^JWT_SECRET=" config.env | cut -d= -f2-)" ]]; then
    JWT_SEC=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c 64)
    sed -i '/^#\s*JWT_SECRET=/d' config.env
    sed -i '/^JWT_SECRET=/d' config.env
    echo "JWT_SECRET=${JWT_SEC}" >> config.env
    info "Generated JWT_SECRET"
else
    info "JWT_SECRET already set"
fi

# DASHBOARD_PASSWORD_HASH (bcrypt) — generated after image build (step 6)

set -a; source config.env; set +a

# ════════════════════════════════════════════════════════════
# 4. Storage configuration
# ════════════════════════════════════════════════════════════
step "Storage configuration"

if [[ -n "${DATA_PATH:-}" ]]; then
    info "DATA_PATH: ${DATA_PATH}"
    mkdir -p "${DATA_PATH}/opensearch"
    chown -R 1000:1000 "${DATA_PATH}/opensearch"

    cat > "${SCRIPT_DIR}/docker-compose.override.yml" <<OVERRIDE
services:
  opensearch:
    volumes:
      - ${DATA_PATH}/opensearch:/usr/share/opensearch/data
OVERRIDE
    info "docker-compose.override.yml generated"
else
    info "Using Docker named volumes"
    rm -f "${SCRIPT_DIR}/docker-compose.override.yml"
fi

# ════════════════════════════════════════════════════════════
# 5. Host OS tuning
# ════════════════════════════════════════════════════════════
step "Host OS tuning"

CURRENT_MAP=$(sysctl -n vm.max_map_count 2>/dev/null || echo "0")
if [[ $CURRENT_MAP -lt 262144 ]]; then
    sysctl -w vm.max_map_count=262144
    info "Set vm.max_map_count=262144"
fi

SYSCTL_CONF="/etc/sysctl.d/99-plan-b-siem.conf"
if [[ ! -f "$SYSCTL_CONF" ]]; then
    cat > "$SYSCTL_CONF" <<'EOF'
vm.max_map_count=262144
net.core.rmem_max=26214400
net.core.rmem_default=262144
EOF
    info "Written ${SYSCTL_CONF}"
fi

# ════════════════════════════════════════════════════════════
# 6. Clean stale state + build + pull
# ════════════════════════════════════════════════════════════
step "Preparing Docker images"

if docker ps -a --format '{{.Names}}' | grep -q "^plan-b-"; then
    info "Removing stale containers from prior install …"
    docker compose --env-file config.env down -v 2>/dev/null || true
    # plan-b-graylog / plan-b-mongodb are v1 containers: keep them in this list
    # so an upgrade from a v1 site removes them. Do not "clean up" as stale.
    for c in plan-b-syslog plan-b-dashboard plan-b-opensearch plan-b-license-checker plan-b-graylog plan-b-mongodb; do
        docker rm -f "$c" 2>/dev/null || true
    done
fi
docker volume ls -q --filter name=plan-b-siem_ | while read -r vol; do
    docker volume rm "$vol" 2>/dev/null || true
done

docker compose --env-file config.env build syslog-receiver dashboard license-checker
info "Local images built"

docker compose --env-file config.env pull opensearch
info "OpenSearch image pulled"

# ── Generate DASHBOARD_PASSWORD_HASH ──
if ! grep -q "^DASHBOARD_PASSWORD_HASH=" config.env 2>/dev/null || \
   [[ -z "$(grep "^DASHBOARD_PASSWORD_HASH=" config.env | cut -d= -f2-)" ]]; then
    info "Generating dashboard password hash..."
    RAW_PW=$(grep "^DASHBOARD_PASSWORD=" config.env | sed "s/^DASHBOARD_PASSWORD=//" | sed "s/^'//;s/'$//")

    # Write a temp JS file to avoid shell escaping issues
    cat > /tmp/plan-b-genhash.js << 'JSEOF'
const bcrypt = require('bcryptjs');
const pw = process.argv[2] || 'changeme';
console.log(bcrypt.hashSync(pw, 12));
JSEOF

    PW_HASH=$(docker run --rm -v /tmp/plan-b-genhash.js:/tmp/genhash.js -w /tmp \
        node:22-alpine sh -c "npm init -y >/dev/null 2>&1 && npm install bcryptjs >/dev/null 2>&1 && node /tmp/genhash.js '${RAW_PW}'" 2>/dev/null | tail -1)
    rm -f /tmp/plan-b-genhash.js

    if [[ -n "$PW_HASH" && "$PW_HASH" == \$2* ]]; then
        sed -i '/^#\s*DASHBOARD_PASSWORD_HASH=/d' config.env
        sed -i '/^DASHBOARD_PASSWORD_HASH=/d' config.env
        # Single-quote the hash to prevent bash interpreting $2a as a variable
        echo "DASHBOARD_PASSWORD_HASH='${PW_HASH}'" >> config.env
        info "Generated DASHBOARD_PASSWORD_HASH"
        set -a; source config.env; set +a
    else
        die "Failed to generate password hash. Got: ${PW_HASH}"
    fi
else
    info "DASHBOARD_PASSWORD_HASH already set"
fi

# ════════════════════════════════════════════════════════════
# 7. Start services
# ════════════════════════════════════════════════════════════
step "Starting SIEM v2 services"

docker compose --env-file config.env up -d opensearch
info "OpenSearch starting …"

TIMEOUT=180; ELAPSED=0
until docker compose --env-file config.env exec -T opensearch \
      curl -sf http://localhost:9200/_cluster/health &>/dev/null; do
    sleep 5; ELAPSED=$((ELAPSED+5))
    [[ $ELAPSED -ge $TIMEOUT ]] && die "OpenSearch failed to start within ${TIMEOUT}s"
    echo -n "."
done
echo ""; info "OpenSearch is healthy"

docker compose --env-file config.env up -d syslog-receiver dashboard
info "Syslog receiver and dashboard starting …"
sleep 5

docker compose --env-file config.env up -d license-checker
info "License checker started"

# ════════════════════════════════════════════════════════════
# 8. Auto-start
# ════════════════════════════════════════════════════════════
step "Configuring auto-start"

IS_WSL2=false
grep -qi microsoft /proc/version 2>/dev/null && IS_WSL2=true

if $IS_WSL2 && [[ -x "${SCRIPT_DIR}/resilience/setup-resilience.sh" ]]; then
    bash "${SCRIPT_DIR}/resilience/setup-resilience.sh" "${SCRIPT_DIR}"
else
    cat > /etc/systemd/system/plan-b-siem.service <<UNIT
[Unit]
Description=Plan-B Systems SIEM v2
After=docker.service network-online.target
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
    systemctl enable plan-b-siem.service
    info "systemd service enabled"
fi

# ════════════════════════════════════════════════════════════
# Done
# ════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║              Installation complete!                  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  Dashboard   : ${BOLD}http://${HOST_IP}:${DASHBOARD_PORT:-3000}${NC}"
echo -e "  Password    : ${BOLD}${DASHBOARD_PASSWORD}${NC}"
echo ""
echo -e "  Client      : ${BOLD}${CLIENT_NAME}${NC}"
echo -e "  Client ID   : ${BOLD}${CLIENT_ID}${NC}"
echo -e "  Retention   : ${BOLD}${RETENTION_DAYS:-730} days${NC}"
echo -e "  Syslog UDP  : ${BOLD}${HOST_IP}:${SYSLOG_UDP_PORT:-514}${NC}"
echo -e "  Syslog TCP  : ${BOLD}${HOST_IP}:${SYSLOG_TCP_PORT:-1514}${NC}"
echo ""
echo -e "  Stack: ${BOLD}docker compose --env-file config.env ps${NC}"
echo -e "  Logs:  ${BOLD}docker compose --env-file config.env logs -f${NC}"
echo ""
