#!/usr/bin/env bash
# ============================================================
# Plan-B Systems SIEM v2 – Health Check
# Verifies all components are running and healthy
# Usage: ./health-check.sh [--quiet] [--fix]
# ============================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; NC='\033[0m'

QUIET=false
FIX=false
ERRORS=0
WARNINGS=0

for arg in "$@"; do
    case "$arg" in
        --quiet)  QUIET=true ;;
        --fix)    FIX=true ;;
    esac
done

SIEM_DIR="/opt/plan-b-siem"
if [[ -f /etc/plan-b-siem.conf ]]; then
    source /etc/plan-b-siem.conf
fi

pass() { $QUIET || echo -e "  ${GREEN}PASS${NC}  $*"; }
fail() { echo -e "  ${RED}FAIL${NC}  $*"; ERRORS=$((ERRORS+1)); }
warn_() { echo -e "  ${YELLOW}WARN${NC}  $*"; WARNINGS=$((WARNINGS+1)); }

$QUIET || echo -e "${BOLD}Plan-B Systems SIEM v2 – Health Check${NC}"
$QUIET || echo -e "$(date '+%Y-%m-%d %H:%M:%S')\n"

# ── 1. Docker daemon ──
$QUIET || echo -e "${BOLD}Docker${NC}"
if docker info &>/dev/null; then
    pass "Docker daemon running"
else
    fail "Docker daemon not running"
    if $FIX; then
        dockerd &>/var/log/dockerd.log &
        sleep 5
        docker info &>/dev/null && { pass "Docker started (fixed)"; ERRORS=$((ERRORS-1)); }
    fi
fi

# ── 2. Containers running ──
$QUIET || echo -e "\n${BOLD}Containers${NC}"
CONTAINERS=(plan-b-opensearch plan-b-syslog plan-b-dashboard plan-b-license-checker)
for cname in "${CONTAINERS[@]}"; do
    STATUS=$(docker inspect --format='{{.State.Status}}' "$cname" 2>/dev/null || echo "not found")
    HEALTH=$(docker inspect --format='{{.State.Health.Status}}' "$cname" 2>/dev/null || echo "none")

    if [[ "$STATUS" == "running" && "$HEALTH" == "healthy" ]]; then
        pass "${cname}: running (healthy)"
    elif [[ "$STATUS" == "running" ]]; then
        warn_ "${cname}: running but health=${HEALTH}"
    else
        fail "${cname}: ${STATUS}"
        if $FIX; then
            docker start "$cname" &>/dev/null
            sleep 3
            NEW_STATUS=$(docker inspect --format='{{.State.Status}}' "$cname" 2>/dev/null || echo "failed")
            [[ "$NEW_STATUS" == "running" ]] && { pass "${cname}: started (fixed)"; ERRORS=$((ERRORS-1)); }
        fi
    fi
done

# ── 3. Dashboard ──
$QUIET || echo -e "\n${BOLD}Dashboard${NC}"
DASH_PORT=3000
if [[ -f "${SIEM_DIR}/config.env" ]]; then
    DASH_PORT=$(grep "^DASHBOARD_PORT=" "${SIEM_DIR}/config.env" 2>/dev/null | cut -d= -f2 || echo "3000")
    DASH_PORT=${DASH_PORT:-3000}
fi
DASH_RESP=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${DASH_PORT}/api/health" --connect-timeout 5 2>/dev/null)
if [[ "$DASH_RESP" == "200" ]]; then
    pass "Dashboard API responding"
else
    fail "Dashboard API not responding (HTTP ${DASH_RESP})"
fi

# ── 4. OpenSearch cluster ──
$QUIET || echo -e "\n${BOLD}OpenSearch${NC}"
OS_HEALTH=$(docker exec plan-b-opensearch curl -s localhost:9200/_cluster/health 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null || echo "unreachable")
if [[ "$OS_HEALTH" == "green" ]]; then
    pass "OpenSearch cluster: green"
elif [[ "$OS_HEALTH" == "yellow" ]]; then
    warn_ "OpenSearch cluster: yellow (single-node is normal)"
else
    fail "OpenSearch cluster: ${OS_HEALTH}"
fi

# ── 5. Syslog receiver ──
$QUIET || echo -e "\n${BOLD}Syslog Receiver${NC}"
SYSLOG_TCP=$(echo "" | timeout 3 bash -c "cat > /dev/tcp/127.0.0.1/1514" 2>/dev/null && echo "ok" || echo "fail")
if [[ "$SYSLOG_TCP" == "ok" ]]; then
    pass "Syslog TCP:1514 accepting connections"
else
    fail "Syslog TCP:1514 not responding"
fi

# ── 6. Port bindings ──
$QUIET || echo -e "\n${BOLD}Port Bindings${NC}"
declare -A PORT_CHECK=(
    ["3000/tcp"]="Dashboard"
    ["1514/tcp"]="Syslog TCP"
)
for port_proto in "${!PORT_CHECK[@]}"; do
    PORT=$(echo "$port_proto" | cut -d/ -f1)
    BOUND=$(ss -tlnp 2>/dev/null | grep ":${PORT} " || echo "")
    if [[ -n "$BOUND" ]]; then
        pass "${PORT_CHECK[$port_proto]} (${port_proto}): listening"
    else
        fail "${PORT_CHECK[$port_proto]} (${port_proto}): not listening"
    fi
done

declare -A UDP_CHECK=(
    ["514/udp"]="Syslog UDP"
)
for port_proto in "${!UDP_CHECK[@]}"; do
    PORT=$(echo "$port_proto" | cut -d/ -f1)
    BOUND=$(ss -ulnp 2>/dev/null | grep ":${PORT} " || echo "")
    if [[ -n "$BOUND" ]]; then
        pass "${UDP_CHECK[$port_proto]} (${port_proto}): listening"
    else
        fail "${UDP_CHECK[$port_proto]} (${port_proto}): not listening"
    fi
done

# ── 7. Disk space ──
$QUIET || echo -e "\n${BOLD}Disk Space${NC}"
DOCKER_ROOT=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo "/var/lib/docker")
FREE_GB=$(df -BG "$DOCKER_ROOT" 2>/dev/null | awk 'NR==2{gsub(/G/,"",$4); print $4}')
if [[ -n "$FREE_GB" ]]; then
    if [[ $FREE_GB -lt 10 ]]; then
        fail "Docker storage: ${FREE_GB} GB free (CRITICAL)"
    elif [[ $FREE_GB -lt 50 ]]; then
        warn_ "Docker storage: ${FREE_GB} GB free (low)"
    else
        pass "Docker storage: ${FREE_GB} GB free"
    fi
fi

# ── Summary ──
echo ""
if [[ $ERRORS -eq 0 && $WARNINGS -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}All checks passed.${NC}"
    exit 0
elif [[ $ERRORS -eq 0 ]]; then
    echo -e "${YELLOW}${BOLD}${WARNINGS} warning(s), no errors.${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}${ERRORS} error(s), ${WARNINGS} warning(s).${NC}"
    exit 1
fi
