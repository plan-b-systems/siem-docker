#!/usr/bin/env bash
# ============================================================
# Plan-B Systems SIEM – WSL Boot Startup Script
# Runs at WSL boot via /etc/wsl.conf [boot] command=
# Ensures Docker + SIEM stack come up after any reboot
# ============================================================
set -uo pipefail

LOG="/var/log/plansb-siem-startup.log"
exec >> "$LOG" 2>&1

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [plansb-startup] $*"; }

log "========== WSL boot detected =========="

# Load SIEM install path
SIEM_DIR="/opt/plansb-siem"
if [[ -f /etc/plansb-siem.conf ]]; then
    source /etc/plansb-siem.conf
fi

if [[ ! -f "${SIEM_DIR}/docker-compose.yml" ]]; then
    log "ERROR: SIEM directory not found at ${SIEM_DIR}"
    exit 1
fi

# ── Apply sysctl tuning (WSL2 doesn't persist these across reboots) ──
if [[ -f /etc/sysctl.d/99-plansb-siem.conf ]]; then
    sysctl -p /etc/sysctl.d/99-plansb-siem.conf 2>/dev/null || true
    log "sysctl tuning applied"
fi

# ── Clean stale processes from previous session ──
if [[ -x "${SIEM_DIR}/resilience/clean-stale-processes.sh" ]]; then
    bash "${SIEM_DIR}/resilience/clean-stale-processes.sh" 2>&1
fi

# ── Start Docker daemon if not running ──
if ! pgrep -x dockerd &>/dev/null; then
    log "Starting Docker daemon..."
    dockerd &>/var/log/dockerd.log &
    DOCKERD_PID=$!
    log "dockerd started (PID ${DOCKERD_PID})"
fi

# ── Wait for Docker to be ready ──
log "Waiting for Docker daemon..."
TIMEOUT=90
ELAPSED=0
while ! docker info &>/dev/null; do
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    if [[ $ELAPSED -ge $TIMEOUT ]]; then
        log "ERROR: Docker daemon failed to start within ${TIMEOUT}s"
        exit 1
    fi
done
log "Docker daemon ready (waited ${ELAPSED}s)"

# ── Start SIEM stack ──
cd "$SIEM_DIR"
log "Starting SIEM stack from ${SIEM_DIR}..."
docker compose --env-file config.env up -d 2>&1
EXIT_CODE=$?

if [[ $EXIT_CODE -eq 0 ]]; then
    log "SIEM stack started successfully"
else
    log "WARNING: docker compose up exited with code ${EXIT_CODE}"
    # Retry once after cleaning stale processes again
    log "Retrying after second cleanup..."
    bash "${SIEM_DIR}/resilience/clean-stale-processes.sh" 2>&1
    sleep 3
    docker compose --env-file config.env up -d 2>&1
    EXIT_CODE=$?
    if [[ $EXIT_CODE -eq 0 ]]; then
        log "SIEM stack started on retry"
    else
        log "ERROR: SIEM stack failed to start after retry (exit ${EXIT_CODE})"
    fi
fi

# ── Wait for Graylog health then log status ──
log "Waiting for Graylog to become healthy..."
TIMEOUT=300
ELAPSED=0
while [[ $ELAPSED -lt $TIMEOUT ]]; do
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' plansb-graylog 2>/dev/null || echo "unknown")
    if [[ "$STATUS" == "healthy" ]]; then
        break
    fi
    sleep 10
    ELAPSED=$((ELAPSED + 10))
done

log "Container status after startup:"
docker ps --format "  {{.Names}}: {{.Status}}" 2>&1 | while read -r line; do
    log "$line"
done

log "========== Startup complete =========="
