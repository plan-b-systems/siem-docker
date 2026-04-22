#!/usr/bin/env bash
# Plan-B Systems SIEM v2 - Linux Bootstrap Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/plan-b-systems/siem-docker/main/install-linux.sh | sudo bash

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║     Plan-B Systems SIEM v2 – Bootstrap Installer     ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

[[ $EUID -ne 0 ]] && { echo -e "${RED}ERROR: Run as root (sudo)${NC}"; exit 1; }

INSTALL_DIR="/opt/plan-b-siem"

# Install git if missing
command -v git &>/dev/null || {
    echo -e "${GREEN}[OK]${NC}    Installing git..."
    apt-get update -qq 2>/dev/null && apt-get install -y -qq git 2>/dev/null || \
    dnf install -y -q git 2>/dev/null || \
    yum install -y -q git 2>/dev/null
}

# Clone or update
if [[ -d "${INSTALL_DIR}/.git" ]]; then
    echo -e "${GREEN}[OK]${NC}    Updating existing installation..."
    cd "$INSTALL_DIR"
    rm -f config.env docker-compose.override.yml 2>/dev/null || true
    git fetch origin v2 && git checkout v2 && git pull origin v2 2>&1 || true
else
    echo -e "${GREEN}[OK]${NC}    Cloning repository..."
    git clone -b v2 https://github.com/plan-b-systems/siem-docker.git "$INSTALL_DIR" 2>&1
fi

cd "$INSTALL_DIR"
chmod +x deploy-ubuntu.sh
echo ""
exec ./deploy-ubuntu.sh </dev/tty
