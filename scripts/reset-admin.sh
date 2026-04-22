#!/bin/bash
# Emergency admin-reset wrapper.
#
# Usage:
#   sudo bash scripts/reset-admin.sh [new-password]
#
# Runs the node-based reset inside the plan-b-dashboard container.
# If no password is given, one is generated.

set -euo pipefail

CONTAINER="${PB_DASHBOARD_CONTAINER:-plan-b-dashboard}"

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "ERROR: container '$CONTAINER' is not running." >&2
  echo "       Start the stack with 'docker compose up -d' first." >&2
  exit 1
fi

if [[ $# -gt 0 ]]; then
  exec docker exec -i "$CONTAINER" node scripts/reset-admin.js "$1"
else
  exec docker exec -i "$CONTAINER" node scripts/reset-admin.js
fi
