#!/usr/bin/env bash
# ============================================================
# Plan-B Systems SIEM – Ubuntu One-Shot Deployment
# ============================================================
# Run this on a fresh Ubuntu 22.04/24.04 machine (bare metal or VM).
# Handles everything: Docker, SIEM stack, auto-start.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/plan-b-systems/siem-docker/main/deploy-ubuntu.sh | sudo bash
#   OR
#   sudo ./deploy-ubuntu.sh
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
step()  { echo -e "\n${BLUE}${BOLD}══ $* ${NC}"; }
die()   { error "$*"; exit 1; }

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║     Plan-B Systems SIEM – Ubuntu Deployment          ║"
echo "║     Graylog 7.2 + OpenSearch 2.x + MongoDB 7.0      ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Root check ──
[[ $EUID -ne 0 ]] && die "This script must be run as root (use sudo)"

# ════════════════════════════════════════════════════════════
# 1. Gather client info
# ════════════════════════════════════════════════════════════
step "Client Configuration"

read -rp "  Client name (short, no spaces, e.g. acme-tlv): " CLIENT_NAME
[[ -z "$CLIENT_NAME" || "$CLIENT_NAME" =~ \  ]] && die "Client name cannot be empty or contain spaces"

read -rp "  Client ID (from Plan-B portal): " CLIENT_ID
[[ -z "$CLIENT_ID" ]] && die "Client ID is required"

# Auto-detect IP
DEFAULT_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
read -rp "  Machine LAN IP [${DEFAULT_IP}]: " HOST_IP
HOST_IP="${HOST_IP:-$DEFAULT_IP}"
[[ -z "$HOST_IP" ]] && die "LAN IP is required"

read -rp "  Graylog admin password (min 8 chars): " ADMIN_PASSWORD
[[ ${#ADMIN_PASSWORD} -lt 8 ]] && die "Password must be at least 8 characters"

read -rp "  Timezone [Asia/Jerusalem]: " TIMEZONE
TIMEZONE="${TIMEZONE:-Asia/Jerusalem}"

read -rp "  Log retention days [730]: " RETENTION_DAYS
RETENTION_DAYS="${RETENTION_DAYS:-730}"

# Auto-calculate heap
TOTAL_RAM_GB=$(( $(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024 / 1024 ))
HEAP_SIZE=$(( TOTAL_RAM_GB / 2 ))
[[ $HEAP_SIZE -lt 1 ]] && HEAP_SIZE=1
HEAP="${HEAP_SIZE}g"
info "Detected ${TOTAL_RAM_GB} GB RAM -> OpenSearch heap: ${HEAP}"

read -rp "  External data path (leave empty for Docker volumes): " DATA_PATH
DATA_PATH="${DATA_PATH:-}"

echo ""
echo -e "  ${BOLD}Configuration Summary:${NC}"
echo "  ─────────────────────────────────"
echo "  Client:     ${CLIENT_NAME}"
echo "  Client ID:  ${CLIENT_ID}"
echo "  LAN IP:     ${HOST_IP}"
echo "  Timezone:   ${TIMEZONE}"
echo "  Retention:  ${RETENTION_DAYS} days"
echo "  Heap:       ${HEAP}"
[[ -n "$DATA_PATH" ]] && echo "  Data Path:  ${DATA_PATH}"
echo ""

read -rp "  Proceed with deployment? (y/n): " CONFIRM
[[ "$CONFIRM" != "y" ]] && { echo "Deployment cancelled."; exit 0; }

# ════════════════════════════════════════════════════════════
# 2. Install prerequisites
# ════════════════════════════════════════════════════════════
step "Installing Prerequisites"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq git gettext-base openssl curl >/dev/null 2>&1
info "System tools installed"

# Docker
if command -v docker &>/dev/null; then
    DOCKER_VER=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")
    info "Docker already installed: ${DOCKER_VER}"
else
    info "Installing Docker..."
    curl -fsSL https://get.docker.com | sh 2>&1 | tail -3
    info "Docker installed"
fi

# Verify Docker is running
if ! docker info &>/dev/null; then
    systemctl start docker 2>/dev/null || dockerd &>/var/log/dockerd.log &
    sleep 5
fi
docker info &>/dev/null || die "Docker failed to start"
info "Docker is running"

# ════════════════════════════════════════════════════════════
# 3. Clone repository
# ════════════════════════════════════════════════════════════
step "Cloning SIEM Repository"

INSTALL_DIR="/opt/plansb-siem"

if [[ -d "${INSTALL_DIR}/.git" ]]; then
    info "Repo exists, pulling latest..."
    cd "$INSTALL_DIR" && git pull origin main 2>&1 || true
else
    git clone https://github.com/plan-b-systems/siem-docker.git "$INSTALL_DIR" 2>&1
fi
info "Repository ready at ${INSTALL_DIR}"

cd "$INSTALL_DIR"

# ════════════════════════════════════════════════════════════
# 4. Generate config.env
# ════════════════════════════════════════════════════════════
step "Generating Configuration"

cp config.env.template config.env

sed -i "s|^CLIENT_NAME=.*|CLIENT_NAME=${CLIENT_NAME}|" config.env
sed -i "s|^CLIENT_ID=.*|CLIENT_ID=${CLIENT_ID}|" config.env
sed -i "s|^GRAYLOG_HOSTNAME=.*|GRAYLOG_HOSTNAME=${HOST_IP}|" config.env
sed -i "s|^HOST_IP=.*|HOST_IP=${HOST_IP}|" config.env
sed -i "s|^GRAYLOG_ADMIN_PASSWORD=.*|GRAYLOG_ADMIN_PASSWORD=${ADMIN_PASSWORD}|" config.env
sed -i "s|^TIMEZONE=.*|TIMEZONE=${TIMEZONE}|" config.env
sed -i "s|^RETENTION_DAYS=.*|RETENTION_DAYS=${RETENTION_DAYS}|" config.env
sed -i "s|^OPENSEARCH_HEAP_SIZE=.*|OPENSEARCH_HEAP_SIZE=${HEAP}|" config.env
sed -i "s|^DATA_PATH=.*|DATA_PATH=${DATA_PATH}|" config.env

info "config.env generated"

# ════════════════════════════════════════════════════════════
# 5. Run install.sh
# ════════════════════════════════════════════════════════════
step "Running SIEM Installer"

chmod +x install.sh
./install.sh

# ════════════════════════════════════════════════════════════
# 6. Open firewall (ufw)
# ════════════════════════════════════════════════════════════
step "Firewall Configuration"

if command -v ufw &>/dev/null; then
    UFW_STATUS=$(ufw status | head -1)
    if [[ "$UFW_STATUS" == *"active"* ]]; then
        ufw allow 9000/tcp comment "PlanB-SIEM Graylog Web" 2>/dev/null || true
        ufw allow 514/udp comment "PlanB-SIEM Syslog UDP" 2>/dev/null || true
        ufw allow 1514/tcp comment "PlanB-SIEM Syslog TCP" 2>/dev/null || true
        ufw allow 12201/udp comment "PlanB-SIEM GELF UDP" 2>/dev/null || true
        ufw allow 12202/tcp comment "PlanB-SIEM GELF TCP" 2>/dev/null || true
        info "UFW rules added"
    else
        info "UFW is not active — skipping firewall rules"
    fi
else
    info "No firewall manager detected — ensure ports 9000, 514, 1514, 12201, 12202 are open"
fi

# ════════════════════════════════════════════════════════════
# 7. Health Check
# ════════════════════════════════════════════════════════════
step "Final Health Check"

sleep 5
if [[ -x "${INSTALL_DIR}/resilience/health-check.sh" ]]; then
    bash "${INSTALL_DIR}/resilience/health-check.sh"
else
    docker compose --env-file config.env ps
fi

# ════════════════════════════════════════════════════════════
# Done
# ════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║              DEPLOYMENT COMPLETE                     ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  Graylog UI  : ${BOLD}https://${HOST_IP}:9000${NC}"
echo -e "  Username    : ${BOLD}admin${NC}"
echo -e "  Password    : ${BOLD}${ADMIN_PASSWORD}${NC}"
echo ""
echo -e "  Client Name : ${CLIENT_NAME}"
echo -e "  Client ID   : ${CLIENT_ID}"
echo -e "  Retention   : ${RETENTION_DAYS} days"
echo ""
echo -e "  CA cert     : ${BOLD}${INSTALL_DIR}/certs/ca.crt${NC}"
echo -e "  Import into browsers to remove the certificate warning."
echo ""
echo -e "  The SIEM will auto-start on every boot via systemd."
echo ""
