#!/usr/bin/env bash
# ============================================================
# Plan-B Systems SIEM v2.1 – Linux One-Shot Deployment
# ============================================================
# Supports Ubuntu 22.04/24.04, Debian 12, RHEL/Rocky 8+
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/plan-b-systems/siem-docker/main/deploy-linux.sh | sudo bash
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
echo "║     Plan-B Systems SIEM v2.1 – Linux Deployment      ║"
echo "║     OpenSearch 2.x + Syslog Receiver + Dashboard     ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

[[ $EUID -ne 0 ]] && die "This script must be run as root (use sudo)"

# ════════════════════════════════════════════════════════════
# 1. Gather client info
# ════════════════════════════════════════════════════════════
step "Client Configuration"

read -rp "  Client name (short, no spaces, e.g. acme-tlv): " CLIENT_NAME
[[ -z "$CLIENT_NAME" || "$CLIENT_NAME" =~ \  ]] && die "Client name cannot be empty or contain spaces"

read -rp "  Client ID (from Plan-B portal): " CLIENT_ID
[[ -z "$CLIENT_ID" ]] && die "Client ID is required"

DEFAULT_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
read -rp "  Machine LAN IP [${DEFAULT_IP}]: " HOST_IP
HOST_IP="${HOST_IP:-$DEFAULT_IP}"
[[ -z "$HOST_IP" ]] && die "LAN IP is required"

read -rp "  Dashboard admin password (min 8 chars): " ADMIN_PASSWORD
[[ ${#ADMIN_PASSWORD} -lt 8 ]] && die "Password must be at least 8 characters"

read -rp "  Timezone [Asia/Jerusalem]: " TIMEZONE
TIMEZONE="${TIMEZONE:-Asia/Jerusalem}"

read -rp "  Log retention days [730]: " RETENTION_DAYS
RETENTION_DAYS="${RETENTION_DAYS:-730}"

TOTAL_RAM_GB=$(( $(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024 / 1024 ))
HEAP_SIZE=$(( TOTAL_RAM_GB / 4 ))
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

# Detect package manager
if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y -qq git openssl curl >/dev/null 2>&1
elif command -v dnf &>/dev/null; then
    dnf install -y -q git openssl curl >/dev/null 2>&1
elif command -v yum &>/dev/null; then
    yum install -y -q git openssl curl >/dev/null 2>&1
fi
info "System tools installed"

if command -v docker &>/dev/null; then
    DOCKER_VER=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")
    info "Docker already installed: ${DOCKER_VER}"
else
    info "Installing Docker..."
    curl -fsSL https://get.docker.com | sh 2>&1 | tail -3
    info "Docker installed"
fi

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

INSTALL_DIR="/opt/plan-b-siem"
SIEM_BRANCH="${SIEM_BRANCH:-main}"

if [[ -d "${INSTALL_DIR}/.git" ]]; then
    info "Repo exists, cleaning and updating..."
    cd "$INSTALL_DIR"
    # Clean generated artifacts from prior install
    rm -f config.env docker-compose.override.yml 2>/dev/null || true
    git fetch origin "$SIEM_BRANCH" 2>&1
    git checkout -B "$SIEM_BRANCH" "origin/$SIEM_BRANCH" 2>&1
else
    git clone -b "$SIEM_BRANCH" https://github.com/plan-b-systems/siem-docker.git "$INSTALL_DIR" 2>&1
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
sed -i "s|^HOST_IP=.*|HOST_IP=${HOST_IP}|" config.env
sed -i "s|^DASHBOARD_PASSWORD=.*|DASHBOARD_PASSWORD='${ADMIN_PASSWORD}'|" config.env
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
# 6. Firewall
# ════════════════════════════════════════════════════════════
step "Firewall Configuration"

if command -v ufw &>/dev/null; then
    UFW_STATUS=$(ufw status | head -1)
    if [[ "$UFW_STATUS" == *"active"* ]]; then
        ufw allow 3000/tcp comment "PlanB-SIEM Dashboard" 2>/dev/null || true
        ufw allow 514/udp comment "PlanB-SIEM Syslog UDP" 2>/dev/null || true
        ufw allow 1514/tcp comment "PlanB-SIEM Syslog TCP" 2>/dev/null || true
        info "UFW rules added"
    else
        info "UFW not active — skipping"
    fi
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-port=3000/tcp 2>/dev/null || true
    firewall-cmd --permanent --add-port=514/udp 2>/dev/null || true
    firewall-cmd --permanent --add-port=1514/tcp 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
    info "firewalld rules added"
else
    info "No firewall manager — ensure ports 3000, 514, 1514 are open"
fi

# ════════════════════════════════════════════════════════════
# 7. Health Check
# ════════════════════════════════════════════════════════════
step "Final Health Check"

sleep 5
if [[ -x "${INSTALL_DIR}/resilience/health-check.sh" ]]; then
    bash "${INSTALL_DIR}/resilience/health-check.sh" || true
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
echo -e "  Dashboard   : ${BOLD}http://${HOST_IP}:3000${NC}"
echo -e "  Password    : ${BOLD}${ADMIN_PASSWORD}${NC}"
echo ""
echo -e "  Client      : ${CLIENT_NAME}"
echo -e "  Client ID   : ${CLIENT_ID}"
echo -e "  Retention   : ${RETENTION_DAYS} days"
echo -e "  Syslog UDP  : ${HOST_IP}:514"
echo -e "  Syslog TCP  : ${HOST_IP}:1514"
echo ""
echo -e "  Stack: ${BOLD}docker compose --env-file config.env ps${NC}"
echo -e "  Logs:  ${BOLD}docker compose --env-file config.env logs -f${NC}"
echo ""
echo -e "  The SIEM will auto-start on every boot via systemd."
echo ""
