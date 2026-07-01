#!/bin/bash
# ============================================================
# Plan-B Systems SIEM – boot convergence (systemd, non-blocking)
# ------------------------------------------------------------
# Triggered ~15s AFTER boot by plan-b-siem-stack.timer, OFF the boot-critical
# path (WSL only waits ~10s for systemd to reach 'running'; a health-gated
# `compose up` on the critical path makes WSL declare init failed and reap the
# distro). Self-heals corrupt RW layers left by unclean WSL shutdowns (Docker
# 29 containerd-snapshotter can leave a container with a nil RWLayer that plain
# `up -d` cannot start). See resilience/REBOOT-SURVIVAL.md.
#   usage: boot-converge.sh [stop]
# ============================================================
set -uo pipefail

SIEM_DIR="/opt/plan-b-siem"
[[ -f /etc/plan-b-siem.conf ]] && source /etc/plan-b-siem.conf
cd "$SIEM_DIR" || exit 1

LOG=/var/log/plan-b-boot-converge.log
exec >>"$LOG" 2>&1

# Detect compose file (Windows pre-built image vs Linux local build) + override
COMPOSE_FILE="docker-compose.yml"
if [[ -f docker-compose.windows.yml ]] && grep -qi microsoft /proc/version 2>/dev/null; then
    COMPOSE_FILE="docker-compose.windows.yml"
fi
CF=(-f "$COMPOSE_FILE")
[[ -f docker-compose.override.yml ]] && CF+=(-f docker-compose.override.yml)
CF+=(--env-file config.env)

# Container names to verify (from the compose project)
mapfile -t CONTAINERS < <(docker compose "${CF[@]}" ps --services 2>/dev/null | sed 's/^/plan-b-/')
[[ ${#CONTAINERS[@]} -eq 0 ]] && CONTAINERS=(plan-b-opensearch plan-b-syslog plan-b-dashboard plan-b-license-checker)

if [[ "${1:-}" == "stop" ]]; then
    echo "$(date '+%F %T') [converge] graceful stop"
    docker compose "${CF[@]}" stop || true
    exit 0
fi

echo "$(date '+%F %T') [converge] start ($COMPOSE_FILE)"
docker compose "${CF[@]}" up -d --remove-orphans || true
sleep 3

need=0
for c in "${CONTAINERS[@]}"; do
    st=$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null || echo missing)
    [[ "$st" == "true" ]] || { echo "$(date '+%F %T') [converge] $c not running (state=$st)"; need=1; }
done

if [[ $need -eq 1 ]]; then
    echo "$(date '+%F %T') [converge] force-recreate (heal corrupt/stale containers)"
    if ! docker compose "${CF[@]}" up -d --force-recreate --remove-orphans; then
        echo "$(date '+%F %T') [converge] force-recreate failed; rm -f + recreate"
        for c in "${CONTAINERS[@]}"; do docker rm -f "$c" 2>/dev/null || true; done
        docker compose "${CF[@]}" up -d --force-recreate --remove-orphans || true
    fi
fi

echo "$(date '+%F %T') [converge] result:"
docker ps --format '  {{.Names}}: {{.Status}}'
