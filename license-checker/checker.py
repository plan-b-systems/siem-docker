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

LICENSE_API_URL      = os.environ.get("LICENSE_API_URL",   "https://api.plan-b.systems/license/check")
CLIENT_ID            = os.environ.get("CLIENT_ID",         "")
GRACE_PERIOD_DAYS    = int(os.environ.get("GRACE_PERIOD_DAYS", "7"))
STATE_FILE           = Path(os.environ.get("STATE_FILE",   "/data/license_state.json"))
LOG_FILE             = Path(os.environ.get("LOG_FILE",     "/data/license_checker.log"))
TZ_NAME              = os.environ.get("TZ",                "UTC")
GRAYLOG_CONTAINER    = os.environ.get("GRAYLOG_CONTAINER",    "plansb-graylog")
OPENSEARCH_CONTAINER = os.environ.get("OPENSEARCH_CONTAINER", "plansb-opensearch")

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
    log.info("Plan-B Systems License Checker  v1.0")
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

    scheduler.start()
    log.info("Scheduler started. License checker running.")

    try:
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        log.info("Shutdown signal received.")
        scheduler.shutdown(wait=False)
        log.info("License checker stopped.")


if __name__ == "__main__":
    main()
