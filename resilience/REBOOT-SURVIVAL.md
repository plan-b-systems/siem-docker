# SIEM reboot-survival — root cause & fix (2026-07-01)

## The real root cause (proven, not theorized)
A **WSL2 distro is idle-shut-down by `wsl.exe` from the Windows side** ~60s after the
last Windows session detaches — **regardless of systemd/dockerd/containers running inside.**
Journal proof from a reaped boot:

```
WSL (init-systemd) ERROR: InitTerminateInstanceInternal: systemctl poweroff did not
terminate the instance in 10000 ms, calling reboot(RB_POWER_OFF)
```

This is why NOTHING in-distro (foreground dockerd, a supervisor loop, even systemd) kept
it alive: the kill comes from outside. The controller is `.wslconfig`:
- `[wsl2] vmIdleTimeout` (default **60000ms**) — VM idle shutdown.
- `[general] instanceIdleTimeout` (WSL 2.4.4+) — distro instance shutdown when no session.

It "ran for days before the Win update" only because the box was never rebooted and a
session/daemon was effectively always attached, so WSL never saw it idle. The update
rebooted it (first real test of unattended restart), exposing: (a) autostart-as-SYSTEM
couldn't restart a per-user distro → 43h dark, and (b) WSL's 60s idle-kill of an
unattended distro. Both now fixed.

## What was changed on the live box (data on D: never touched)
| Area | Change | Rollback |
|---|---|---|
| `%UserProfile%\.wslconfig` | `vmIdleTimeout=-1` + `[general] instanceIdleTimeout=-1` — **the actual fix** | `.wslconfig.bak` |
| `/etc/wsl.conf` | `[boot] systemd=true` (removed old `command=`) | `wsl.conf.pre-systemd`, `wsl.conf.bak` |
| systemd | installed; `containerd`,`docker`,`docker.socket` enabled | — |
| `/etc/systemd/system/plan-b-siem-stack.service` + `.timer` | `OnBootSec=15` → `boot-converge.sh`, OFF the boot-critical path (WSL only waits ~10s for systemd to reach `running`; a blocking compose up made WSL declare init failed and reap) | delete units |
| `resilience/boot-converge.sh` | self-heals corrupt RW layers (Docker 29 containerd-snapshotter can leave `RWLayer nil` after an unclean stop; plain `up -d` then can't start the container) via force-recreate; uses the override so data stays on D: | — |
| `C:\PlanB-SIEM\PlanB-SIEM-Startup.ps1` | line 57 `compose up` now includes `-f docker-compose.override.yml` (was omitting it → recreated OpenSearch on the empty named volume = apparent data loss) | git |

## Proven
- Distro holds `Running` 120s+ untouched (idle survival — was impossible before).
- Full `wsl --shutdown` + real `PlanB-SIEM-Autostart` task → systemd boots → boot-converge
  brings stack up on `/mnt/d/SIEMdata/opensearch` → all 4 healthy → ports 3000/514/1514
  reachable → stays up. End-to-end reboot survival.

## OPEN items
1. **`PlanB-SIEM-UDP-Relay` task runs as SYSTEM** (same bug class as the old Autostart).
   SYSTEM can't reliably see the per-user distro → UDP/514 syslog forwarding is unreliable
   (log shows "forwarded 0 so far"). Re-register as `B-PLAN\PC` (Password logon) — needs the
   PC account password. Consider WSL `networkingMode=mirrored` to drop the relay + portproxy
   entirely (bigger change, test off-box).
2. A real Windows reboot at the console for final sign-off (validated by faithful simulation,
   not yet by an actual OS reboot).

## Propagation to the installer (for ALL future clients) — do off-box, test, then PR to main
1. **`resilience/windows/Register-ScheduledTask.ps1:57`** and **`deploy-windows.ps1:~480`**:
   `-User "SYSTEM"` → the **installing user** (per-user distro requires it). Also register
   the UDP-relay task as that user, not SYSTEM.
2. **Write `.wslconfig`** during install: `[wsl2] vmIdleTimeout=-1` + `[general] instanceIdleTimeout=-1`.
3. **Enable systemd** in the WSL image: `wsl.conf [boot] systemd=true`; install systemd;
   `systemctl enable docker containerd`; ship `plan-b-siem-stack.service` + `.timer` +
   `boot-converge.sh`. Reconcile the two conflicting `/etc/wsl.conf` definitions
   (`wsl-image/Dockerfile` vs `resilience/setup-resilience.sh`).
4. **`PlanB-SIEM-Startup.ps1`**: compose up must include `docker-compose.override.yml` (done here).
5. `resilience/wsl-startup.sh` is now UNUSED under systemd (kept as backup on box). Decide:
   remove from boot path in installer, or delete.
6. Consider gitignoring `docker-compose.override.yml` (per-client; currently untracked-not-ignored).
