#!/usr/bin/env python3
"""
Plan-B Systems – License Checker Service
=========================================
State machine that validates the client license daily (12:00 local time)
and controls Graylog / OpenSearch availability accordingly.

Auth model (v2 — 2026-04-23, ed25519/X25519, zero plaintext secrets)
--------------------------------------------------------------------
On first boot this service generates an ed25519 keypair (signing) and
an X25519 keypair (encryption) in /data. Only the public halves ever
cross the wire. The portal verifies incoming license-checks by
signature; AI API keys arrive hybrid-encrypted (sealed box) so only
this installation's private key can decrypt them.

See docs/on-prem-secret-lifecycle.md in pbsiem for the full design.

States
------
  NORMAL       – License valid. Daily check at 12:00.
  GRACE_PERIOD – API unreachable. Services running. Grace clock ticking.
  EXPIRED      – License inactive or grace period elapsed.
                 Services stopped. Check every 10 minutes.

Transitions
-----------
  NORMAL      → GRACE_PERIOD : API unreachable
  NORMAL      → EXPIRED      : active=false
  GRACE_PERIOD → NORMAL      : API reachable + active=true
  GRACE_PERIOD → EXPIRED     : grace window elapsed
  EXPIRED     → NORMAL       : active=true  (services restarted)
"""

import os
import json
import secrets
import logging
import datetime
import time
import hashlib
import base64
from pathlib import Path
from logging.handlers import RotatingFileHandler

import docker
import requests
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

# v2 crypto — ed25519 + X25519 sealed box
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Configuration ────────────────────────────────────────────────────────

LICENSE_API_URL      = os.environ.get("LICENSE_API_URL",   "https://siemsys.plan-b.co.il/api/license/check")
HEALTH_API_URL       = os.environ.get("HEALTH_API_URL",    "https://siemsys.plan-b.co.il/api/health-report")
CLIENT_ID            = os.environ.get("CLIENT_ID",         "")
# Legacy — still read for backward-compat with v1 deployments that haven't been upgraded.
# Once this installation bootstraps with public keys, CLIENT_SECRET is never consulted again.
LEGACY_CLIENT_SECRET = os.environ.get("CLIENT_SECRET",     "")
GRACE_PERIOD_DAYS    = int(os.environ.get("GRACE_PERIOD_DAYS", "7"))
STATE_FILE           = Path(os.environ.get("STATE_FILE",   "/data/license_state.json"))
LOG_FILE             = Path(os.environ.get("LOG_FILE",     "/data/license_checker.log"))
AI_KEY_FILE          = Path(os.environ.get("AI_KEY_FILE",  "/data/ai_key.json"))
TZ_NAME              = os.environ.get("TZ",                "UTC")
SYSLOG_CONTAINER     = os.environ.get("SYSLOG_CONTAINER",     "plan-b-syslog")
OPENSEARCH_CONTAINER = os.environ.get("OPENSEARCH_CONTAINER", "plan-b-opensearch")
DASHBOARD_CONTAINER  = os.environ.get("DASHBOARD_CONTAINER",  "plan-b-dashboard")
VERSION              = os.environ.get("VERSION",              "2.01")

# Keypair storage — /data is the Docker volume mounted rw into this container.
DATA_DIR                = Path("/data")
SIGN_PRIVATE_KEY_PATH   = DATA_DIR / "plan-b-sign-private.pem"
SIGN_PUBLIC_KEY_PATH    = DATA_DIR / "plan-b-sign-public.pem"
ENCRYPT_PRIVATE_KEY_PATH = DATA_DIR / "plan-b-encrypt-private.pem"
ENCRYPT_PUBLIC_KEY_PATH  = DATA_DIR / "plan-b-encrypt-public.pem"

# ── State constants ──────────────────────────────────────────────────────

STATE_NORMAL  = "NORMAL"
STATE_GRACE   = "GRACE_PERIOD"
STATE_EXPIRED = "EXPIRED"

# ── Logging setup ────────────────────────────────────────────────────────

def setup_logging() -> logging.Logger:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s [%(levelname)-8s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    file_handler = RotatingFileHandler(str(LOG_FILE), maxBytes=10 * 1024 * 1024, backupCount=10, encoding="utf-8")
    file_handler.setFormatter(fmt)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)
    log = logging.getLogger("license_checker")
    log.setLevel(logging.INFO)
    log.addHandler(file_handler)
    log.addHandler(console_handler)
    return log

log = setup_logging()

# ══════════════════════════════════════════════════════════════════════════
# Keypair lifecycle
# ══════════════════════════════════════════════════════════════════════════

def _write_pem(path: Path, pem_bytes: bytes, mode: int = 0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem_bytes)
    try:
        os.chmod(path, mode)
    except Exception:
        pass  # non-fatal on some filesystems

def ensure_keypairs() -> tuple[ed25519.Ed25519PrivateKey, x25519.X25519PrivateKey]:
    """Load keypairs from /data, generating them on first boot. Also heals
    after a file was deleted. Returns (signing_private, encrypt_private)."""
    if SIGN_PRIVATE_KEY_PATH.exists():
        sign_priv = serialization.load_pem_private_key(SIGN_PRIVATE_KEY_PATH.read_bytes(), password=None)
        if not isinstance(sign_priv, ed25519.Ed25519PrivateKey):
            log.warning("Signing key file exists but is not Ed25519 — regenerating")
            sign_priv = None
    else:
        sign_priv = None

    if sign_priv is None:
        log.info("Generating new Ed25519 signing keypair")
        sign_priv = ed25519.Ed25519PrivateKey.generate()
        _write_pem(
            SIGN_PRIVATE_KEY_PATH,
            sign_priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )
        _write_pem(
            SIGN_PUBLIC_KEY_PATH,
            sign_priv.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            mode=0o644,
        )

    if ENCRYPT_PRIVATE_KEY_PATH.exists():
        enc_priv = serialization.load_pem_private_key(ENCRYPT_PRIVATE_KEY_PATH.read_bytes(), password=None)
        if not isinstance(enc_priv, x25519.X25519PrivateKey):
            log.warning("Encrypt key file exists but is not X25519 — regenerating")
            enc_priv = None
    else:
        enc_priv = None

    if enc_priv is None:
        log.info("Generating new X25519 encryption keypair")
        enc_priv = x25519.X25519PrivateKey.generate()
        _write_pem(
            ENCRYPT_PRIVATE_KEY_PATH,
            enc_priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
        )
        _write_pem(
            ENCRYPT_PUBLIC_KEY_PATH,
            enc_priv.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
            mode=0o644,
        )

    return sign_priv, enc_priv


def regenerate_keypairs() -> tuple[ed25519.Ed25519PrivateKey, x25519.X25519PrivateKey]:
    """Wipe the current keypairs and generate fresh ones. Used during
    portal-initiated rotation, when the portal has signalled
    rotation_requested=true on its most recent license-check response."""
    for p in (SIGN_PRIVATE_KEY_PATH, SIGN_PUBLIC_KEY_PATH, ENCRYPT_PRIVATE_KEY_PATH, ENCRYPT_PUBLIC_KEY_PATH):
        try:
            if p.exists():
                p.unlink()
        except Exception as exc:
            log.warning("Failed to remove %s during rotation: %s", p, exc)
    return ensure_keypairs()


def read_sign_public_pem() -> str:
    return SIGN_PUBLIC_KEY_PATH.read_text(encoding="utf-8")

def read_encrypt_public_pem() -> str:
    return ENCRYPT_PUBLIC_KEY_PATH.read_text(encoding="utf-8")


def pem_to_header_body(pem: str) -> str:
    """Strip PEM BEGIN/END lines + whitespace down to a single-line base64
    body safe for HTTP header transmission. Portal reconstructs PEM via
    ensurePem() / bodyToPem() on receipt."""
    return "".join(
        line for line in pem.split("\n") if line and not line.startswith("-----")
    )

# ══════════════════════════════════════════════════════════════════════════
# Canonical signing message — MUST match pbsiem src/lib/on-prem-crypto.ts
# ══════════════════════════════════════════════════════════════════════════

def build_sign_message(purpose: str, client_id: str, timestamp_ms: int, nonce: str) -> str:
    return f"{purpose}:{client_id}:{timestamp_ms}:{nonce}"


def sign_message(priv: ed25519.Ed25519PrivateKey, message: str) -> str:
    sig = priv.sign(message.encode("utf-8"))
    return base64.b64encode(sig).decode("ascii")

# ══════════════════════════════════════════════════════════════════════════
# Sealed-box decrypt (matches pbsiem sealedBoxEncrypt exactly)
# Envelope layout: ephemeral_pub(32) || iv(12) || ciphertext(n) || auth_tag(16), base64
# ══════════════════════════════════════════════════════════════════════════

def sealed_box_decrypt(envelope_b64: str, recipient_private: x25519.X25519PrivateKey) -> str:
    envelope = base64.b64decode(envelope_b64)
    if len(envelope) < 32 + 12 + 16:
        raise ValueError("envelope_too_short")

    eph_pub_raw = envelope[:32]
    iv          = envelope[32:44]
    tag         = envelope[-16:]
    ct          = envelope[44:-16]

    # Rebuild ephemeral X25519 public key from 32-byte raw
    ephemeral_public = x25519.X25519PublicKey.from_public_bytes(eph_pub_raw)
    shared = recipient_private.exchange(ephemeral_public)

    # Recipient public key — raw form — for HKDF salt (must match Node side exactly)
    recipient_pub_raw = recipient_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=eph_pub_raw + recipient_pub_raw,
        info=b"pbsiem-sealed-box-v1",
    )
    aes_key = hkdf.derive(shared)

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(iv, ct + tag, associated_data=None)
    return plaintext.decode("utf-8")

# ── State persistence ────────────────────────────────────────────────────

def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception as exc:
            log.error("Failed to load state file: %s – using defaults", exc)
    return {
        "status":           STATE_NORMAL,
        "first_failure":    None,
        "last_check":       None,
        "last_result":      None,
        "services_stopped": False,
        "bootstrapped":     False,
        "install_time":     datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2)
    except Exception as exc:
        log.error("Failed to save state file: %s", exc)

# ── Docker helpers (unchanged from v1) ───────────────────────────────────

def _docker_client():
    try:
        return docker.from_env()
    except Exception as exc:
        log.error("Cannot connect to Docker daemon: %s", exc)
        return None

def _find_container(client, name: str):
    try:
        for c in client.containers.list(all=True):
            if name.lower() in c.name.lower():
                return c
    except Exception as exc:
        log.error("Error listing containers: %s", exc)
    return None

def stop_services() -> bool:
    client = _docker_client()
    if client is None:
        return False
    success = True
    for name in [SYSLOG_CONTAINER, DASHBOARD_CONTAINER, OPENSEARCH_CONTAINER]:
        container = _find_container(client, name)
        if container is None:
            log.warning("Container not found: %s", name)
            continue
        if container.status == "running":
            try:
                log.info("Stopping container: %s …", container.name)
                container.stop(timeout=45)
                log.info("Stopped: %s", container.name)
            except Exception as exc:
                log.error("Failed to stop %s: %s", container.name, exc)
                success = False
    return success

def start_services() -> bool:
    client = _docker_client()
    if client is None:
        return False
    success = True
    for name in [OPENSEARCH_CONTAINER, SYSLOG_CONTAINER, DASHBOARD_CONTAINER]:
        container = _find_container(client, name)
        if container is None:
            log.warning("Container not found: %s", name)
            continue
        if container.status != "running":
            try:
                log.info("Starting container: %s …", container.name)
                container.start()
                log.info("Started: %s", container.name)
            except Exception as exc:
                log.error("Failed to start %s: %s", container.name, exc)
                success = False
    return success

# ── AI key persistence ───────────────────────────────────────────────────

def save_ai_key(api_key: str, daily_budget: int, ai_tier: str) -> None:
    try:
        ai_data = {
            "api_key": api_key,
            "daily_budget": daily_budget,
            "ai_tier": ai_tier,
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        AI_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(AI_KEY_FILE, "w", encoding="utf-8") as f:
            json.dump(ai_data, f, indent=2)
        log.info("AI key saved (tier=%s, budget=%d/day)", ai_tier, daily_budget)
    except Exception as exc:
        log.error("Failed to save AI key: %s", exc)

def remove_ai_key() -> None:
    try:
        if AI_KEY_FILE.exists():
            AI_KEY_FILE.unlink()
            log.info("AI key removed")
    except Exception as exc:
        log.error("Failed to remove AI key: %s", exc)

# ══════════════════════════════════════════════════════════════════════════
# License API — v2 signed flow
# ══════════════════════════════════════════════════════════════════════════

def call_license_api(
    sign_priv: ed25519.Ed25519PrivateKey,
    enc_priv: x25519.X25519PrivateKey,
    state: dict,
) -> tuple[bool, bool | None, str | None, dict]:
    """
    Perform one license-check call against the portal with full v2 signed
    auth. Returns (api_reachable, active, expires_str, raw_response).

    Handles all three purposes:
      - bootstrap: first-ever call; portal learns our public keys
      - check:    normal daily poll
      - rotate:   portal requested a rotation on last call

    Side effects:
      - Stores ai_key.json on a successful authenticated response
      - Writes state['bootstrapped'] = True after first successful bootstrap
      - On rotation, generates new keypairs before signing
    """
    if not CLIENT_ID:
        log.error("CLIENT_ID env is empty — cannot call license API")
        return False, None, None, {}

    # Decide purpose
    bootstrapped = bool(state.get("bootstrapped"))
    rotation_pending = bool(state.get("rotation_pending"))
    purpose = "check"
    if not bootstrapped:
        purpose = "bootstrap"
    elif rotation_pending:
        purpose = "rotate"

    # For rotation: generate the NEW keypair before signing, so we can send
    # proof of possession of BOTH old and new.
    new_sign_priv: ed25519.Ed25519PrivateKey | None = None
    new_enc_priv:  x25519.X25519PrivateKey | None  = None
    if purpose == "rotate":
        new_sign_priv = ed25519.Ed25519PrivateKey.generate()
        new_enc_priv  = x25519.X25519PrivateKey.generate()

    ts = int(time.time() * 1000)
    nonce = secrets.token_hex(16)
    message = build_sign_message(purpose, CLIENT_ID, ts, nonce)
    signature = sign_message(sign_priv, message)

    headers = {
        "X-Signature": signature,
        "X-Timestamp": str(ts),
        "X-Nonce":     nonce,
        "X-Purpose":   purpose,
    }

    if purpose == "bootstrap":
        headers["X-Public-Key-Sign"]    = pem_to_header_body(read_sign_public_pem())
        headers["X-Public-Key-Encrypt"] = pem_to_header_body(read_encrypt_public_pem())

    if purpose == "rotate" and new_sign_priv is not None and new_enc_priv is not None:
        new_sign_pub_pem = new_sign_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        new_enc_pub_pem = new_enc_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        new_sig = sign_message(new_sign_priv, message)
        headers["X-New-Public-Key-Sign"]    = pem_to_header_body(new_sign_pub_pem)
        headers["X-New-Public-Key-Encrypt"] = pem_to_header_body(new_enc_pub_pem)
        headers["X-New-Signature"]          = new_sig

    # Legacy fallback: if we have no bootstrap yet AND there's a LEGACY_CLIENT_SECRET
    # from config.env, ALSO send it in Authorization header. Portal will fall back to
    # the legacy path if the signed path doesn't find a matching installation row.
    # This is the migration bridge — once bootstrap succeeds, legacy header is ignored.
    if not bootstrapped and LEGACY_CLIENT_SECRET:
        headers["Authorization"] = f"Bearer {LEGACY_CLIENT_SECRET}"

    url = f"{LICENSE_API_URL}?client_id={CLIENT_ID}"
    try:
        resp = requests.get(url, headers=headers, timeout=30, verify=True)
        resp.raise_for_status()
        data = resp.json()
        active  = bool(data.get("active", False))
        expires = data.get("expiry_date") or data.get("expires") or "unknown"
        authenticated = bool(data.get("authenticated", False))
        ip_mismatch   = bool(data.get("ip_mismatch", False))
        log.info(
            "API response: purpose=%s active=%s authenticated=%s expires=%s%s",
            purpose, active, authenticated, expires,
            "  ip_mismatch=true" if ip_mismatch else "",
        )

        # Bootstrap success — persist keys as "registered", next call is "check"
        if purpose == "bootstrap" and authenticated:
            state["bootstrapped"] = True
            log.info("Bootstrap accepted — keys registered with portal")

        # Rotation accepted — swap to new keys atomically
        if purpose == "rotate" and data.get("rotated") and new_sign_priv and new_enc_priv:
            _write_pem(
                SIGN_PRIVATE_KEY_PATH,
                new_sign_priv.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ),
            )
            _write_pem(
                SIGN_PUBLIC_KEY_PATH,
                new_sign_priv.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
                mode=0o644,
            )
            _write_pem(
                ENCRYPT_PRIVATE_KEY_PATH,
                new_enc_priv.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ),
            )
            _write_pem(
                ENCRYPT_PUBLIC_KEY_PATH,
                new_enc_priv.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
                mode=0o644,
            )
            state["rotation_pending"] = False
            log.info("Key rotation accepted — swapped to new keypair")

        # AI key — prefer sealed-box (v2), fall back to legacy AES-CBC (v1)
        if active and authenticated:
            if data.get("ai_key_sealed"):
                try:
                    decrypted = sealed_box_decrypt(data["ai_key_sealed"], enc_priv)
                    save_ai_key(
                        decrypted,
                        int(data.get("ai_daily_budget", 0)),
                        str(data.get("ai_tier", "NONE")),
                    )
                except Exception as exc:
                    log.error("Failed to decrypt sealed-box AI key: %s", exc)
            elif data.get("ai_key_encrypted") and LEGACY_CLIENT_SECRET:
                # Legacy path — AES-256-CBC, key = sha256(CLIENT_SECRET)
                try:
                    legacy = _legacy_decrypt_ai_key(data["ai_key_encrypted"], LEGACY_CLIENT_SECRET)
                    if legacy:
                        save_ai_key(
                            legacy,
                            int(data.get("ai_daily_budget", 0)),
                            str(data.get("ai_tier", "NONE")),
                        )
                except Exception as exc:
                    log.error("Legacy AI key decryption failed: %s", exc)
            elif str(data.get("ai_tier", "NONE")) == "NONE":
                remove_ai_key()

        # Portal may signal us: rotation_requested → flip flag so next call is purpose=rotate
        if data.get("rotation_requested"):
            state["rotation_pending"] = True
            log.info("Portal requested key rotation — will rotate on next cycle")

        # IP mismatch or grace-elapsed signals → remove AI key
        if data.get("ip_mismatch") or not active:
            remove_ai_key()

        return True, active, expires, data

    except requests.exceptions.SSLError as exc:
        log.error("SSL error contacting license API: %s", exc)
    except requests.exceptions.ConnectionError as exc:
        log.error("Connection error contacting license API: %s", exc)
    except requests.exceptions.Timeout:
        log.error("License API request timed out")
    except Exception as exc:
        log.error("Unexpected error contacting license API: %s", exc)
    return False, None, None, {}


def _legacy_decrypt_ai_key(encrypted: str, secret: str) -> str | None:
    """AES-256-CBC decrypt for the v1 legacy path."""
    try:
        from binascii import unhexlify
        from Crypto.Cipher import AES
        parts = encrypted.split(":")
        if len(parts) != 2:
            return None
        iv = unhexlify(parts[0])
        ct = unhexlify(parts[1])
        key = hashlib.sha256(secret.encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)
        pad = pt[-1]
        return pt[:-pad].decode("utf-8")
    except Exception:
        return None

# ── Health metrics collection ────────────────────────────────────────────

def _get_container_status(client, name: str) -> str:
    container = _find_container(client, name)
    if container is None:
        return "not_found"
    status = container.status
    if status == "running":
        try:
            health = container.attrs.get("State", {}).get("Health", {}).get("Status", "")
            if health == "unhealthy":
                return "unhealthy"
        except Exception:
            pass
        return "running"
    return "stopped"

def _get_disk_usage() -> dict:
    try:
        import shutil
        for path in ["/data", "/usr/share/opensearch/data", "/"]:
            if os.path.exists(path):
                usage = shutil.disk_usage(path)
                return {
                    "disk_total_gb": round(usage.total / (1024**3), 1),
                    "disk_used_gb": round(usage.used / (1024**3), 1),
                    "disk_percent": round((usage.used / usage.total) * 100, 1),
                }
    except Exception as exc:
        log.debug("Disk usage error: %s", exc)
    return {}

def _get_memory_usage() -> dict:
    try:
        with open("/proc/meminfo", "r") as f:
            lines = {l.split(":")[0]: int(l.split(":")[1].strip().split()[0]) for l in f if ":" in l}
        total = lines.get("MemTotal", 0) / (1024 * 1024)
        available = lines.get("MemAvailable", 0) / (1024 * 1024)
        used = total - available
        return {
            "mem_total_gb": round(total, 1),
            "mem_used_gb": round(used, 1),
            "mem_percent": round((used / total) * 100, 1) if total > 0 else 0,
        }
    except Exception as exc:
        log.debug("Memory usage error: %s", exc)
    return {}

def _get_uptime_hours() -> float | None:
    try:
        with open("/proc/uptime", "r") as f:
            return round(float(f.read().split()[0]) / 3600, 1)
    except Exception:
        return None

def _get_opensearch_stats(client) -> dict:
    result = {}
    container = _find_container(client, OPENSEARCH_CONTAINER)
    if container is None or container.status != "running":
        return result
    try:
        exit_code, output = container.exec_run("curl -sf http://localhost:9200/_cluster/health", demux=True)
        if exit_code == 0 and output[0]:
            health = json.loads(output[0].decode())
            result["os_cluster_health"] = health.get("status", "unknown")
        exit_code, output = container.exec_run("curl -sf http://localhost:9200/_stats/store,docs", demux=True)
        if exit_code == 0 and output[0]:
            stats = json.loads(output[0].decode())
            all_stats = stats.get("_all", {}).get("primaries", {})
            result["os_doc_count"] = all_stats.get("docs", {}).get("count", 0)
            result["os_store_size_gb"] = round(all_stats.get("store", {}).get("size_in_bytes", 0) / (1024**3), 2)
            result["os_index_count"] = len(stats.get("indices", {}))
    except Exception as exc:
        log.debug("OpenSearch stats error: %s", exc)
    return result

def collect_health() -> dict:
    client = _docker_client()
    metrics = {"client_id": CLIENT_ID, "version": VERSION}
    metrics.update(_get_disk_usage())
    metrics.update(_get_memory_usage())
    metrics["uptime_hours"] = _get_uptime_hours()
    if client:
        metrics["syslog_status"] = _get_container_status(client, SYSLOG_CONTAINER)
        metrics["opensearch_status"] = _get_container_status(client, OPENSEARCH_CONTAINER)
        metrics["dashboard_status"] = _get_container_status(client, DASHBOARD_CONTAINER)
        metrics["license_checker_status"] = "running"
        metrics.update(_get_opensearch_stats(client))
    return metrics

def send_health_report() -> None:
    try:
        metrics = collect_health()
        resp = requests.post(HEALTH_API_URL, json=metrics, timeout=30, verify=True)
        if resp.status_code == 200:
            log.info(
                "Health report sent: disk=%s%% mem=%s%% containers=%s/%s/%s cluster=%s",
                metrics.get("disk_percent", "?"),
                metrics.get("mem_percent", "?"),
                metrics.get("syslog_status", "?"),
                metrics.get("opensearch_status", "?"),
                metrics.get("dashboard_status", "?"),
                metrics.get("os_cluster_health", "?"),
            )
        else:
            log.warning("Health report failed: HTTP %d", resp.status_code)
    except Exception as exc:
        log.debug("Health report error: %s", exc)

# ── Scheduler ─────────────────────────────────────────────────────────────

scheduler: BackgroundScheduler = BackgroundScheduler(timezone=TZ_NAME)

def _reschedule_expired_mode() -> None:
    log.info("Switching to EXPIRED mode: checking every 10 minutes")
    try:
        scheduler.reschedule_job("main_check", trigger=IntervalTrigger(minutes=10))
    except Exception:
        pass

def _reschedule_normal_mode() -> None:
    log.info("Switching to NORMAL mode: checking daily at 12:00 (%s)", TZ_NAME)
    try:
        scheduler.reschedule_job("main_check", trigger=CronTrigger(hour=12, minute=0, timezone=TZ_NAME))
    except Exception:
        pass

# ── Core check logic ─────────────────────────────────────────────────────

# Keypairs loaded at startup and kept in module globals (APScheduler calls
# `run_license_check` without args — simpler than shuttling keys through).
SIGN_PRIV: ed25519.Ed25519PrivateKey | None = None
ENC_PRIV:  x25519.X25519PrivateKey | None   = None

def run_license_check() -> None:
    state = load_state()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    state["last_check"] = now_iso
    prev_status = state["status"]

    log.info("─" * 60)
    log.info("License check  |  client=%s  |  state=%s", CLIENT_ID, prev_status)

    assert SIGN_PRIV is not None and ENC_PRIV is not None, "keypairs must be loaded"
    api_ok, active, expires, _raw = call_license_api(SIGN_PRIV, ENC_PRIV, state)

    if api_ok:
        state["last_result"] = {"active": active, "expires": expires, "at": now_iso}
        state["first_failure"] = None
        if active:
            if state["status"] in (STATE_EXPIRED, STATE_GRACE):
                log.info("License is ACTIVE. Restarting SIEM services …")
                if start_services():
                    state["status"] = STATE_NORMAL
                    state["services_stopped"] = False
                    log.info("STATE → NORMAL  (services restarted)")
                    if prev_status == STATE_EXPIRED:
                        _reschedule_normal_mode()
                else:
                    log.error("Service restart failed – will retry next cycle")
            else:
                log.info("License valid. Services running normally. Expires: %s", expires)
        else:
            if state["status"] != STATE_EXPIRED:
                log.warning("License INACTIVE (expires=%s). Stopping SIEM services …", expires)
                if stop_services():
                    state["status"] = STATE_EXPIRED
                    state["services_stopped"] = True
                    log.warning("STATE → EXPIRED  (services stopped)")
                    _reschedule_expired_mode()
                else:
                    log.error("Failed to stop services – will retry next cycle")
            else:
                log.info("License still inactive (expires=%s). Services remain stopped.", expires)
    else:
        if state["status"] == STATE_EXPIRED:
            log.warning("API unreachable – already EXPIRED. Keeping services stopped.")
        elif state["status"] == STATE_GRACE:
            first = datetime.datetime.fromisoformat(state["first_failure"])
            if first.tzinfo is None:
                first = first.replace(tzinfo=datetime.timezone.utc)
            grace_end = first + datetime.timedelta(days=GRACE_PERIOD_DAYS)
            remaining = grace_end - datetime.datetime.now(datetime.timezone.utc)
            if remaining.total_seconds() <= 0:
                log.warning("Grace period of %d days has elapsed. Stopping SIEM services …", GRACE_PERIOD_DAYS)
                if stop_services():
                    state["status"] = STATE_EXPIRED
                    state["services_stopped"] = True
                    log.warning("STATE → EXPIRED  (grace period expired)")
                    _reschedule_expired_mode()
            else:
                days_left = int(remaining.total_seconds() // 86400)
                hrs_left  = int((remaining.total_seconds() % 86400) // 3600)
                log.warning("API unreachable – grace period active (%dd %dh remaining)", days_left, hrs_left)
        else:
            state["status"] = STATE_GRACE
            state["first_failure"] = now_iso
            log.warning("STATE → GRACE_PERIOD  (API unreachable – %d day grace window started)", GRACE_PERIOD_DAYS)

    save_state(state)
    log.info("Check complete  |  new state=%s  |  bootstrapped=%s  |  rotation_pending=%s",
             state["status"], state.get("bootstrapped", False), state.get("rotation_pending", False))
    log.info("─" * 60)

# ── Entry point ──────────────────────────────────────────────────────────

def main() -> None:
    global SIGN_PRIV, ENC_PRIV

    log.info("=" * 60)
    log.info("Plan-B Systems License Checker  v%s  (v2 signed-auth)", VERSION)
    log.info("Client ID   : %s", CLIENT_ID)
    log.info("License API : %s", LICENSE_API_URL)
    log.info("Grace period: %d days", GRACE_PERIOD_DAYS)
    log.info("Timezone    : %s", TZ_NAME)
    log.info("=" * 60)

    SIGN_PRIV, ENC_PRIV = ensure_keypairs()
    log.info("Keypairs ready:")
    log.info("  signing  pub fingerprint: %s", SIGN_PUBLIC_KEY_PATH.read_text(encoding='utf-8').splitlines()[1][:32])
    log.info("  encrypt  pub fingerprint: %s", ENCRYPT_PUBLIC_KEY_PATH.read_text(encoding='utf-8').splitlines()[1][:32])

    log.info("Running startup license check …")
    run_license_check()

    state = load_state()
    if state["status"] == STATE_EXPIRED:
        initial_trigger = IntervalTrigger(minutes=10)
        log.info("Scheduler: EXPIRED mode (every 10 minutes)")
    else:
        initial_trigger = CronTrigger(hour=12, minute=0, timezone=TZ_NAME)
        log.info("Scheduler: NORMAL mode (daily at 12:00 %s)", TZ_NAME)

    scheduler.add_job(
        run_license_check, trigger=initial_trigger, id="main_check",
        name="License check", replace_existing=True, max_instances=1, coalesce=True,
    )
    scheduler.add_job(
        send_health_report, trigger=IntervalTrigger(hours=1), id="health_report",
        name="Health report", replace_existing=True, max_instances=1, coalesce=True,
    )

    log.info("Sending initial health report …")
    send_health_report()

    scheduler.start()
    log.info("Scheduler started. License checker + health reporting running.")

    try:
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        log.info("Shutdown signal received.")
        scheduler.shutdown(wait=False)
        log.info("License checker stopped.")


if __name__ == "__main__":
    main()
