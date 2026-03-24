#!/usr/bin/env bash
# ============================================================
# Plan-B Systems SIEM – TLS Certificate Generator
# Generates a local CA and a server certificate for Graylog.
# Called automatically by install.sh; can also be run manually
# to rotate certificates.
#
# Usage:
#   ./certs/generate-certs.sh [config.env]
#
# Outputs (in the same directory as this script):
#   ca.key       – CA private key  (keep secret)
#   ca.crt       – CA certificate  (import into browsers/clients)
#   graylog.key  – Graylog server private key
#   graylog.csr  – Certificate signing request
#   graylog.crt  – Graylog server certificate signed by local CA
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${1:-${SCRIPT_DIR}/../config.env}"

# Load config.env if present
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    set -a; source "$ENV_FILE"; set +a
fi

# Defaults (overridden by config.env)
GRAYLOG_HOSTNAME="${GRAYLOG_HOSTNAME:-localhost}"
CERT_COUNTRY="${CERT_COUNTRY:-IL}"
CERT_STATE="${CERT_STATE:-Tel_Aviv}"
CERT_CITY="${CERT_CITY:-Tel_Aviv}"
CERT_ORG="${CERT_ORG:-Plan-B_Systems}"
CERT_OU="${CERT_OU:-SIEM}"
CERT_DAYS="${CERT_DAYS:-3650}"   # 10-year validity for on-prem appliance

cd "$SCRIPT_DIR"

echo "──────────────────────────────────────────"
echo "  Plan-B Systems – TLS Certificate Generator"
echo "  Hostname : ${GRAYLOG_HOSTNAME}"
echo "  Validity : ${CERT_DAYS} days"
echo "──────────────────────────────────────────"

# ── 1. Generate CA private key ───────────────────────────────
if [[ ! -f ca.key ]]; then
    echo "[1/5] Generating CA private key …"
    openssl genrsa -out ca.key 4096
    chmod 600 ca.key   # CA key stays private
else
    echo "[1/5] CA private key already exists – skipping"
fi

# ── 2. Self-sign CA certificate ──────────────────────────────
if [[ ! -f ca.crt ]]; then
    echo "[2/5] Generating self-signed CA certificate …"
    openssl req -new -x509 \
        -key ca.key \
        -out ca.crt \
        -days "$CERT_DAYS" \
        -subj "/C=${CERT_COUNTRY}/ST=${CERT_STATE}/L=${CERT_CITY}/O=${CERT_ORG}/OU=${CERT_OU} CA/CN=${CERT_ORG} Root CA"
else
    echo "[2/5] CA certificate already exists – skipping"
fi

# ── 3. Generate server private key ───────────────────────────
echo "[3/5] Generating Graylog server private key …"
openssl genrsa -out graylog.key 4096
# 640 + world-readable so Graylog (uid 1100) can read it inside the container
chmod 644 graylog.key

# ── 4. Create CSR with SAN ───────────────────────────────────
echo "[4/5] Creating certificate signing request …"

# Build SAN list: always include localhost and 127.0.0.1 for healthchecks
SAN="DNS:${GRAYLOG_HOSTNAME},DNS:localhost,IP:127.0.0.1"
# Add HOST_IP if defined and non-empty
if [[ -n "${HOST_IP:-}" ]]; then
    SAN="${SAN},IP:${HOST_IP}"
fi

# Write temporary openssl extension config
EXTFILE=$(mktemp)
cat > "$EXTFILE" <<OPENSSL_EXT
[req]
distinguished_name = req_distinguished_name
req_extensions     = v3_req
prompt             = no

[req_distinguished_name]
C  = ${CERT_COUNTRY}
ST = ${CERT_STATE}
L  = ${CERT_CITY}
O  = ${CERT_ORG}
OU = ${CERT_OU}
CN = ${GRAYLOG_HOSTNAME}

[v3_req]
subjectAltName = ${SAN}
keyUsage       = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
OPENSSL_EXT

openssl req -new \
    -key graylog.key \
    -out graylog.csr \
    -config "$EXTFILE"

# ── 5. Sign with local CA ────────────────────────────────────
echo "[5/5] Signing server certificate with local CA …"

V3EXT=$(mktemp)
cat > "$V3EXT" <<V3_EXT
subjectAltName    = ${SAN}
keyUsage          = digitalSignature, keyEncipherment
extendedKeyUsage  = serverAuth
basicConstraints  = CA:FALSE
V3_EXT

openssl x509 -req \
    -in graylog.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out graylog.crt \
    -days "$CERT_DAYS" \
    -sha256 \
    -extfile "$V3EXT"

rm -f "$EXTFILE" "$V3EXT"

# ── Verify ───────────────────────────────────────────────────
echo ""
echo "Certificate details:"
openssl x509 -in graylog.crt -noout -subject -issuer -dates -ext subjectAltName
echo ""
echo "Verifying chain …"
openssl verify -CAfile ca.crt graylog.crt && echo "Chain OK"

echo ""
echo "Files generated:"
ls -lh "$SCRIPT_DIR"/{ca.key,ca.crt,graylog.key,graylog.csr,graylog.crt} 2>/dev/null || true
echo ""
echo "Next steps:"
echo "  • Import certs/ca.crt into browsers/clients to trust the Graylog UI"
echo "  • Keep certs/ca.key and certs/graylog.key with permissions 600"
