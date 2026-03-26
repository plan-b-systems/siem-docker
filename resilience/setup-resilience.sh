#!/usr/bin/env bash
# ============================================================
# Plan-B Systems SIEM – Resilience Setup
# Installs all auto-recovery components for WSL2 deployment
# Must be run as root inside WSL
# Usage: sudo ./resilience/setup-resilience.sh [SIEM_DIR]
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
step()  { echo -e "\n${BLUE}${BOLD}══ $* ${NC}"; }
die()   { error "$*"; exit 1; }

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║     Plan-B Systems SIEM – Resilience Setup           ║"
echo "║     Auto-recovery for WSL2 deployments               ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Root check ──
[[ $EUID -ne 0 ]] && die "This script must be run as root (use sudo)"

# ── WSL2 check ──
if ! grep -qi microsoft /proc/version 2>/dev/null; then
    die "This script is for WSL2 deployments only"
fi

# ── Determine SIEM directory ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIEM_DIR="${1:-$(dirname "$SCRIPT_DIR")}"

if [[ ! -f "${SIEM_DIR}/docker-compose.yml" ]]; then
    die "SIEM directory not found at ${SIEM_DIR}. Pass the path as argument."
fi
info "SIEM directory: ${SIEM_DIR}"

# ════════════════════════════════════════════════════════════
# 1. Save SIEM path for boot scripts
# ════════════════════════════════════════════════════════════
step "Saving SIEM configuration"

cat > /etc/plansb-siem.conf <<EOF
# Plan-B Systems SIEM – install path (used by startup scripts)
SIEM_DIR="${SIEM_DIR}"
EOF
info "Written /etc/plansb-siem.conf"

# ════════════════════════════════════════════════════════════
# 2. Configure /etc/wsl.conf
# ════════════════════════════════════════════════════════════
step "Configuring WSL boot"

# Back up existing wsl.conf
if [[ -f /etc/wsl.conf ]]; then
    cp /etc/wsl.conf /etc/wsl.conf.backup.$(date +%Y%m%d%H%M%S)
    info "Backed up /etc/wsl.conf"
fi

cat > /etc/wsl.conf <<EOF
[boot]
systemd=true
command=${SIEM_DIR}/resilience/wsl-startup.sh

[network]
generateResolvConf=false
EOF
info "Written /etc/wsl.conf (systemd=true + boot command)"

# ════════════════════════════════════════════════════════════
# 3. Make scripts executable
# ════════════════════════════════════════════════════════════
step "Setting script permissions"

chmod +x "${SIEM_DIR}/resilience/wsl-startup.sh"
chmod +x "${SIEM_DIR}/resilience/clean-stale-processes.sh"
chmod +x "${SIEM_DIR}/resilience/health-check.sh"
info "Scripts marked executable"

# ════════════════════════════════════════════════════════════
# 4. Install systemd service (belt-and-suspenders with boot command)
# ════════════════════════════════════════════════════════════
step "Installing systemd service"

# Disable old service if present
if systemctl is-enabled plansb-siem.service &>/dev/null; then
    systemctl disable plansb-siem.service 2>/dev/null || true
    info "Disabled old plansb-siem.service"
fi

cat > /etc/systemd/system/plansb-siem.service <<EOF
[Unit]
Description=Plan-B Systems SIEM Stack
After=docker.service network-online.target
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${SIEM_DIR}
ExecStartPre=${SIEM_DIR}/resilience/clean-stale-processes.sh
ExecStart=/usr/bin/docker compose --env-file ${SIEM_DIR}/config.env -f ${SIEM_DIR}/docker-compose.yml up -d
ExecStop=/usr/bin/docker compose --env-file ${SIEM_DIR}/config.env -f ${SIEM_DIR}/docker-compose.yml down
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable plansb-siem.service
info "systemd service installed and enabled"

# ════════════════════════════════════════════════════════════
# 5. Enable Docker service for systemd auto-start
# ════════════════════════════════════════════════════════════
step "Enabling Docker auto-start"

if systemctl list-unit-files docker.service &>/dev/null; then
    systemctl enable docker.service 2>/dev/null || true
    info "Docker service enabled for systemd"
else
    warn "Docker systemd unit not found — Docker will be started by wsl-startup.sh directly"
fi

# ════════════════════════════════════════════════════════════
# 6. Copy Windows scripts
# ════════════════════════════════════════════════════════════
step "Installing Windows startup scripts"

# Detect Windows user profile path
WIN_USER_PROFILE=$(cmd.exe /C "echo %USERPROFILE%" 2>/dev/null | tr -d '\r' || echo "")
if [[ -z "$WIN_USER_PROFILE" ]]; then
    # Fallback: find it from /mnt/c/Users
    WIN_USER=$(ls /mnt/c/Users/ | grep -v -E "^(Public|Default|All Users|Default User|desktop.ini|\\\$)" | head -1)
    WIN_INSTALL_DIR="/mnt/c/PlanB-SIEM"
else
    WIN_INSTALL_DIR="/mnt/c/PlanB-SIEM"
fi

mkdir -p "$WIN_INSTALL_DIR"
cp "${SIEM_DIR}/resilience/windows/PlanB-SIEM-Startup.ps1" "$WIN_INSTALL_DIR/"
cp "${SIEM_DIR}/resilience/windows/Register-ScheduledTask.ps1" "$WIN_INSTALL_DIR/"
info "Copied PowerShell scripts to C:\\PlanB-SIEM\\"

# ════════════════════════════════════════════════════════════
# 7. Set up health check cron (every 5 minutes)
# ════════════════════════════════════════════════════════════
step "Setting up health check cron"

CRON_LINE="*/5 * * * * ${SIEM_DIR}/resilience/health-check.sh --quiet --fix >> /var/log/plansb-siem-health.log 2>&1"
(crontab -l 2>/dev/null | grep -v "plansb.*health-check" || true; echo "$CRON_LINE") | crontab -
info "Health check cron installed (every 5 minutes with auto-fix)"

# ════════════════════════════════════════════════════════════
# Done
# ════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║          Resilience setup complete!                  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo -e "  ${BOLD}What was installed:${NC}"
echo "  - /etc/wsl.conf         → systemd + boot startup script"
echo "  - /etc/plansb-siem.conf → SIEM install path"
echo "  - systemd service       → plansb-siem.service (with stale process cleanup)"
echo "  - Cron job              → health check every 5 min with auto-fix"
echo "  - C:\\PlanB-SIEM\\        → Windows startup + scheduled task scripts"
echo ""
echo -e "  ${BOLD}${YELLOW}NEXT STEPS (required):${NC}"
echo ""
echo "  1. From PowerShell (as Administrator), register the scheduled task:"
echo -e "     ${BOLD}C:\\PlanB-SIEM\\Register-ScheduledTask.ps1${NC}"
echo ""
echo "  2. Restart WSL to activate the new wsl.conf:"
echo -e "     ${BOLD}wsl --shutdown${NC}  (from PowerShell)"
echo ""
echo "  3. Reopen the Ubuntu terminal — everything should auto-start."
echo ""
echo -e "  ${BOLD}Verification:${NC}"
echo -e "  - Run: ${BOLD}${SIEM_DIR}/resilience/health-check.sh${NC}"
echo -e "  - Logs: ${BOLD}/var/log/plansb-siem-startup.log${NC}"
echo -e "  - Win:  ${BOLD}C:\\PlanB-SIEM\\startup.log${NC}"
echo ""
