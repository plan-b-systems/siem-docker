#!/usr/bin/env python3
"""
Plan-B Systems – License Checker Service
=========================================
State machine that validates the client license daily (12:00 local time)
and controls Graylog / OpenSearch availability accordingly.

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
import logging
import datetime
import time
from pathlib import Path
from logging.handlers import RotatingFileHandler

import docker
import requests
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

# ── Configuration ────────────────────────────────────────────────────────

LICENSE_API_URL      = os.environ.get("LICENSE_API_URL",   "https://siemsys.plan-b.co.il/api/license/check")
HEALTH_API_URL       = os.environ.get("HEALTH_API_URL",    "https://siemsys.plan-b.co.il/api/health-report")
CLIENT_ID            = os.environ.get("CLIENT_ID",         "")
GRACE_PERIOD_DAYS    = int(os.environ.get("GRACE_PERIOD_DAYS", "7"))
STATE_FILE           = Path(os.environ.get("STATE_FILE",   "/data/license_state.json"))
LOG_FILE             = Path(os.environ.get("LOG_FILE",     "/data/license_checker.log"))
TZ_NAME              = os.environ.get("TZ",                "UTC")
GRAYLOG_CONTAINER    = os.environ.get("GRAYLOG_CONTAINER",    "plansb-graylog")
OPENSEARCH_CONTAINER = os.environ.get("OPENSEARCH_CONTAINER", "plansb-opensearch")
MONGODB_CONTAINER    = os.environ.get("MONGODB_CONTAINER",    "plansb-mongodb")
VERSION              = os.environ.get("VERSION",              "1.01")

# ── State constants ──────────────────────────────────────────────────────

STATE_NORMAL  = "NORMAL"
STATE_GRACE   = "GRACE_PERIOD"
STATE_EXPIRED = "EXPIRED"

# ── Logging setup ────────────────────────────────────────────────────────

def setup_logging() -> logging.Logger:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s [%(levelname)-8s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")

    file_handler = RotatingFileHandler(
        str(LOG_FILE), maxBytes=10 * 1024 * 1024, backupCount=10, encoding="utf-8"
    )
    file_handler.setFormatter(fmt)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)

    log = logging.getLogger("license_checker")
    log.setLevel(logging.INFO)
    log.addHandler(file_handler)
    log.addHandler(console_handler)
    return log


log = setup_logging()

# ── State persistence ────────────────────────────────────────────────────

def load_state() -> dict:
    """Load persisted state; return sensible defaults for first boot."""
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
        "install_time":     datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2)
    except Exception as exc:
        log.error("Failed to save state file: %s", exc)

# ── Docker helpers ───────────────────────────────────────────────────────

def _docker_client():
    try:
        return docker.from_env()
    except Exception as exc:
        log.error("Cannot connect to Docker daemon: %s", exc)
        return None


def _find_container(client, name: str):
    """Return container whose .name contains *name* (case-insensitive)."""
    try:
        for c in client.containers.list(all=True):
            if name.lower() in c.name.lower():
                return c
    except Exception as exc:
        log.error("Error listing containers: %s", exc)
    return None


def stop_services() -> bool:
    """Gracefully stop Graylog then OpenSearch.  MongoDB is left running."""
    client = _docker_client()
    if client is None:
        return False

    success = True
    for name in [GRAYLOG_CONTAINER, OPENSEARCH_CONTAINER]:
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
        else:
            log.info("Container %s already stopped (status=%s)", container.name, container.status)
    return success


def start_services() -> bool:
    """Start OpenSearch first, then Graylog."""
    client = _docker_client()
    if client is None:
        return False

    success = True
    for name in [OPENSEARCH_CONTAINER, GRAYLOG_CONTAINER]:
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
        else:
            log.info("Container %s is already running", container.name)
    return success

# ── License API ──────────────────────────────────────────────────────────

def call_license_api() -> tuple[bool, bool | None, str | None]:
    """
    Returns (api_reachable, active, expires_str).
    api_reachable=False means network/timeout error.
    """
    url = f"{LICENSE_API_URL}?client_id={CLIENT_ID}"
    try:
        resp = requests.get(url, timeout=30, verify=True)
        resp.raise_for_status()
        data = resp.json()
        active  = bool(data.get("active", False))
        expires = data.get("expires", "unknown")
        log.info("API response: active=%s  expires=%s", active, expires)
        return True, active, expires
    except requests.exceptions.SSLError as exc:
        log.error("SSL error contacting license API: %s", exc)
    except requests.exceptions.ConnectionError as exc:
        log.error("Connection error contacting license API: %s", exc)
    except requests.exceptions.Timeout:
        log.error("License API request timed out")
    except Exception as exc:
        log.error("Unexpected error contacting license API: %s", exc)
    return False, None, None

# ── Health metrics collection ────────────────────────────────────────────

def _get_container_status(client, name: str) -> str:
    """Return container status: running, stopped, unhealthy, or not_found."""
    container = _find_container(client, name)
    if container is None:
        return "not_found"
    status = container.status  # running, exited, paused, etc.
    if status == "running":
        # Check health if available
        try:
            health = container.attrs.get("State", {}).get("Health", {}).get("Status", "")
            if health == "unhealthy":
                return "unhealthy"
        except Exception:
            pass
        return "running"
    return "stopped"


def _get_disk_usage() -> dict:
    """Get disk usage of the data volume (where OpenSearch stores data)."""
    try:
        import shutil
        # Check /usr/share/opensearch/data (mounted volume) or fallback to /
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
    """Get system memory usage."""
    try:
        with open("/proc/meminfo", "r") as f:
            lines = {l.split(":")[0]: int(l.split(":")[1].strip().split()[0])
                     for l in f if ":" in l}
        total = lines.get("MemTotal", 0) / (1024 * 1024)  # GB
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
    """Get system uptime in hours."""
    try:
        with open("/proc/uptime", "r") as f:
            return round(float(f.read().split()[0]) / 3600, 1)
    except Exception:
        return None


def _get_opensearch_stats(client) -> dict:
    """Query OpenSearch for cluster health and index stats."""
    result = {}
    container = _find_container(client, OPENSEARCH_CONTAINER)
    if container is None or container.status != "running":
        return result
    try:
        # Cluster health
        exit_code, output = container.exec_run(
            "curl -sf http://localhost:9200/_cluster/health", demux=True
        )
        if exit_code == 0 and output[0]:
            health = json.loads(output[0].decode())
            result["os_cluster_health"] = health.get("status", "unknown")

        # Index stats
        exit_code, output = container.exec_run(
            "curl -sf http://localhost:9200/_stats/store,docs", demux=True
        )
        if exit_code == 0 and output[0]:
            stats = json.loads(output[0].decode())
            all_stats = stats.get("_all", {}).get("primaries", {})
            result["os_doc_count"] = all_stats.get("docs", {}).get("count", 0)
            result["os_store_size_gb"] = round(
                all_stats.get("store", {}).get("size_in_bytes", 0) / (1024**3), 2
            )
            result["os_index_count"] = len(stats.get("indices", {}))
    except Exception as exc:
        log.debug("OpenSearch stats error: %s", exc)
    return result


def collect_health() -> dict:
    """Collect all system health metrics."""
    client = _docker_client()
    metrics = {
        "client_id": CLIENT_ID,
        "version": VERSION,
    }

    # Disk & Memory
    metrics.update(_get_disk_usage())
    metrics.update(_get_memory_usage())
    metrics["uptime_hours"] = _get_uptime_hours()

    # Container statuses
    if client:
        metrics["graylog_status"] = _get_container_status(client, GRAYLOG_CONTAINER)
        metrics["opensearch_status"] = _get_container_status(client, OPENSEARCH_CONTAINER)
        metrics["mongodb_status"] = _get_container_status(client, MONGODB_CONTAINER)
        metrics["license_checker_status"] = "running"

        # OpenSearch stats
        metrics.update(_get_opensearch_stats(client))

    return metrics


def send_health_report() -> None:
    """Collect health metrics and send to the portal."""
    try:
        metrics = collect_health()
        resp = requests.post(HEALTH_API_URL, json=metrics, timeout=30, verify=True)
        if resp.status_code == 200:
            log.info("Health report sent: disk=%s%% mem=%s%% containers=%s/%s/%s cluster=%s",
                     metrics.get("disk_percent", "?"),
                     metrics.get("mem_percent", "?"),
                     metrics.get("graylog_status", "?"),
                     metrics.get("opensearch_status", "?"),
                     metrics.get("mongodb_status", "?"),
                     metrics.get("os_cluster_health", "?"))
        else:
            log.warning("Health report failed: HTTP %d", resp.status_code)
    except Exception as exc:
        log.debug("Health report error: %s", exc)


# ── Scheduler (module-level so jobs can reschedule themselves) ───────────

scheduler: BackgroundScheduler = BackgroundScheduler(timezone=TZ_NAME)


def _reschedule_expired_mode() -> None:
    log.info("Switching to EXPIRED mode: checking every 10 minutes")
    try:
        scheduler.reschedule_job(
            "main_check",
            trigger=IntervalTrigger(minutes=10),
        )
    except Exception:
        pass  # Job not yet added (startup check) — scheduler will pick correct trigger after


def _reschedule_normal_mode() -> None:
    log.info("Switching to NORMAL mode: checking daily at 12:00 (%s)", TZ_NAME)
    try:
        scheduler.reschedule_job(
            "main_check",
            trigger=CronTrigger(hour=12, minute=0, timezone=TZ_NAME),
        )
    except Exception:
        pass  # Job not yet added (startup check) — scheduler will pick correct trigger after

# ── Core check logic ─────────────────────────────────────────────────────

def run_license_check() -> None:
    state = load_state()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    state["last_check"] = now_iso
    prev_status = state["status"]

    log.info("─" * 60)
    log.info("License check  |  client=%s  |  state=%s", CLIENT_ID, prev_status)

    api_ok, active, expires = call_license_api()

    if api_ok:
        state["last_result"]   = {"active": active, "expires": expires, "at": now_iso}
        state["first_failure"] = None   # reset grace clock on any successful API call

        if active:
            # ── LICENSE VALID ────────────────────────────────────────
            if state["status"] in (STATE_EXPIRED, STATE_GRACE):
                log.info("License is ACTIVE. Restarting SIEM services …")
                if start_services():
                    state["status"]           = STATE_NORMAL
                    state["services_stopped"] = False
                    log.info("STATE → NORMAL  (services restarted)")
                    if prev_status == STATE_EXPIRED:
                        _reschedule_normal_mode()
                else:
                    log.error("Service restart failed – will retry next cycle")
            else:
                log.info("License valid. Services running normally. Expires: %s", expires)
        else:
            # ── LICENSE INACTIVE ─────────────────────────────────────
            if state["status"] != STATE_EXPIRED:
                log.warning("License INACTIVE (expires=%s). Stopping SIEM services …", expires)
                if stop_services():
                    state["status"]           = STATE_EXPIRED
                    state["services_stopped"] = True
                    log.warning("STATE → EXPIRED  (services stopped)")
                    _reschedule_expired_mode()
                else:
                    log.error("Failed to stop services – will retry next cycle")
            else:
                log.info("License still inactive (expires=%s). Services remain stopped.", expires)

    else:
        # ── API UNREACHABLE ──────────────────────────────────────────
        if state["status"] == STATE_EXPIRED:
            log.warning("API unreachable – already EXPIRED. Keeping services stopped.")

        elif state["status"] == STATE_GRACE:
            first = datetime.datetime.fromisoformat(state["first_failure"])
            # Ensure timezone-aware for comparison (legacy state files may be naive UTC)
            if first.tzinfo is None:
                first = first.replace(tzinfo=datetime.timezone.utc)
            grace_end = first + datetime.timedelta(days=GRACE_PERIOD_DAYS)
            remaining = grace_end - datetime.datetime.now(datetime.timezone.utc)

            if remaining.total_seconds() <= 0:
                log.warning(
                    "Grace period of %d days has elapsed. Stopping SIEM services …",
                    GRACE_PERIOD_DAYS,
                )
                if stop_services():
                    state["status"]           = STATE_EXPIRED
                    state["services_stopped"] = True
                    log.warning("STATE → EXPIRED  (grace period expired)")
                    _reschedule_expired_mode()
            else:
                days_left = int(remaining.total_seconds() // 86400)
                hrs_left  = int((remaining.total_seconds() % 86400) // 3600)
                log.warning(
                    "API unreachable – grace period active (%dd %dh remaining)",
                    days_left, hrs_left,
                )

        else:  # STATE_NORMAL
            state["status"]       = STATE_GRACE
            state["first_failure"] = now_iso
            log.warning(
                "STATE → GRACE_PERIOD  (API unreachable – %d day grace window started)",
                GRACE_PERIOD_DAYS,
            )

    save_state(state)
    log.info("Check complete  |  new state=%s", state["status"])
    log.info("─" * 60)

# ── Entry point ──────────────────────────────────────────────────────────

def main() -> None:
    log.info("=" * 60)
    log.info("Plan-B Systems License Checker  v%s", VERSION)
    log.info("Client ID   : %s", CLIENT_ID)
    log.info("License API : %s", LICENSE_API_URL)
    log.info("Grace period: %d days", GRACE_PERIOD_DAYS)
    log.info("Timezone    : %s", TZ_NAME)
    log.info("=" * 60)

    # ── Initial check on startup ─────────────────────────────
    log.info("Running startup license check …")
    run_license_check()

    # ── Configure scheduler based on post-startup state ──────
    state = load_state()

    if state["status"] == STATE_EXPIRED:
        initial_trigger = IntervalTrigger(minutes=10)
        log.info("Scheduler: EXPIRED mode (every 10 minutes)")
    else:
        initial_trigger = CronTrigger(hour=12, minute=0, timezone=TZ_NAME)
        log.info("Scheduler: NORMAL mode (daily at 12:00 %s)", TZ_NAME)

    scheduler.add_job(
        run_license_check,
        trigger=initial_trigger,
        id="main_check",
        name="License check",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )

    # ── Health reporting — every hour ────────────────────────
    scheduler.add_job(
        send_health_report,
        trigger=IntervalTrigger(hours=1),
        id="health_report",
        name="Health report",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )

    # ── Send initial health report on startup ─────────────
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
