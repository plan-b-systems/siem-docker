#!/usr/bin/env bash
# ============================================================
# Plan-B Systems SIEM – Clean stale Docker processes & ports
# Called before docker compose up to prevent port conflicts
# after unclean shutdown / power outage
# ============================================================
set -uo pipefail

LOG_TAG="[plansb-clean]"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') ${LOG_TAG} $*"; }

# Kill stale docker-proxy processes from previous session
if pgrep -f docker-proxy &>/dev/null; then
    log "Killing stale docker-proxy processes..."
    pkill -9 -f docker-proxy 2>/dev/null || true
    sleep 1
fi

# Kill stale containerd-shim processes
if pgrep -f containerd-shim &>/dev/null; then
    DOCKER_PID=$(pgrep -x dockerd 2>/dev/null || echo "")
    if [[ -z "$DOCKER_PID" ]]; then
        log "Killing orphaned containerd-shim processes (no dockerd running)..."
        pkill -9 -f containerd-shim 2>/dev/null || true
        sleep 1
    fi
fi

# Remove stale Docker PID file if Docker is not running
if [[ -f /var/run/docker.pid ]]; then
    PID=$(cat /var/run/docker.pid 2>/dev/null || echo "")
    if [[ -n "$PID" ]] && ! kill -0 "$PID" 2>/dev/null; then
        log "Removing stale Docker PID file..."
        rm -f /var/run/docker.pid
    fi
fi

# Remove stale Docker socket if Docker is not running
if [[ -S /var/run/docker.sock ]]; then
    if ! pgrep -x dockerd &>/dev/null; then
        log "Removing stale Docker socket..."
        rm -f /var/run/docker.sock
    fi
fi

# Check SIEM ports for stale bindings
SIEM_PORTS_TCP=(9000 1514 12202)
SIEM_PORTS_UDP=(514 12201)

for port in "${SIEM_PORTS_TCP[@]}"; do
    PID=$(fuser "${port}/tcp" 2>/dev/null | tr -d ' ' || echo "")
    if [[ -n "$PID" ]]; then
        PROC=$(ps -p "$PID" -o comm= 2>/dev/null || echo "unknown")
        if [[ "$PROC" == "docker-proxy" ]]; then
            log "Killing stale docker-proxy on TCP port ${port} (PID ${PID})..."
            kill -9 "$PID" 2>/dev/null || true
        fi
    fi
done

for port in "${SIEM_PORTS_UDP[@]}"; do
    PID=$(fuser "${port}/udp" 2>/dev/null | tr -d ' ' || echo "")
    if [[ -n "$PID" ]]; then
        PROC=$(ps -p "$PID" -o comm= 2>/dev/null || echo "unknown")
        if [[ "$PROC" == "docker-proxy" ]]; then
            log "Killing stale docker-proxy on UDP port ${port} (PID ${PID})..."
            kill -9 "$PID" 2>/dev/null || true
        fi
    fi
done

log "Stale process cleanup complete."
