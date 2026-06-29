# On-Prem SIEM — Deployment & Troubleshooting Runbook

> Operational runbook for the on-prem stack (`siem-docker`). Written from the first
> live client deployment (Hammer Globinsky / המר גלובינסקי, `client_id ISO-vX0IswxDVFBpjNzU`,
> MSP Baronit). Box: Windows host running WSL2, LAN IP `10.0.0.11`, WSL distro `PlanB-SIEM`.

---

## 1. Architecture

```
LAN sources                         Windows host (10.0.0.11)            WSL2 (PlanB-SIEM)            Cloud (pbsiem portal)
-----------                         ------------------------            -----------------            ---------------------
Firewall  --UDP 514-->  [Win FW rule UDP514] -> UDP relay --> 172.30.x:514 --> docker: plan-b-syslog ---\
Desktops  --TCP 1514--> [netsh portproxy 1514] ------------> 172.30.x:1514 --> (parsers/)               |--> OpenSearch
SentinelOne (pulled by the syslog-receiver poller) <-------------------------- plan-b-syslog [s1]       |    logs-{client_id}-YYYY.MM
                                                                               plan-b-license-checker --+--> /api/license/check
                                                                               plan-b-dashboard (UI+AI) <-- (license, S1 creds, AI key, sealed)
```

- **Containers:** `plan-b-opensearch`, `plan-b-syslog` (syslog receiver + S1 poller + parsers), `plan-b-dashboard` (Next.js UI + AI chat), `plan-b-license-checker`.
- **Host paths:** `C:\PlanB-SIEM\` (startup.ps1, udp-relay.ps1, logs). **WSL repo:** `/opt/plan-b-siem`. **Shared data volume:** `/data` (s1_integration.json, ai_key.json, portal_status.json).
- **Scheduled tasks (SYSTEM, AtStartup):** `PlanB-SIEM-Autostart` (starts WSL/docker/containers + portproxy + FW rules), `PlanB-SIEM-UDP-Relay` (UDP 514 -> WSL).
- **Index pattern:** `logs-{client_id-lowercased}-YYYY.MM`. Single-tenant per box (one client_id); tell devices apart by the `source`/`host` field.

---

## 2. Per-client prerequisites (the bootstrap chain — fails SILENTLY if skipped)

The box only receives AI key / S1 creds / config AFTER it bootstraps, and bootstrap needs a portal **`AWAITING_INSTALL` OnPremInstallation slot** for the client.

1. **Portal:** create the client + an **ON_PREM subscription** + the **install slot** (now auto-created at provisioning via pbsiem PR #115; backfill old clients via `POST /api/admin/infra/installations/backfill`). No slot ⇒ `/api/license/check` returns `authenticated=False` forever, nothing surfaces it.
2. **AI tier:** set `Client.ai_tier` (`STARTER`/`PRO`/`UNLIMITED`) to match the package. **Auto-grant from the subscription is NOT built yet — set it manually.** Then restart the license-checker.
3. **SentinelOne:** enter the S1 integration in the portal and **Test it to ACTIVE** (admin "add integration" defaults INACTIVE).
4. **⚠ NEVER delete/recreate a client that has a live on-prem install** — `OnPremInstallation.client` cascade-deletes the slot **and** the SENTINELONE integration, leaving the box silently broken (was `Cascade`, tightened to `Restrict` + a delete-guard in PR #115).

---

## 3. Install / Update

- **Fresh install:** `deploy-windows.ps1` (or `install.ps1`) — provisions WSL, containers, `netsh portproxy` (3000/514/1514), Windows FW rules, and the two scheduled tasks (autostart + UDP relay). Uses `down -v` → **wipes data; fresh installs only.**
- **Update (safe, preserves data):**
  ```powershell
  irm https://raw.githubusercontent.com/plan-b-systems/siem-docker/main/update.ps1 | iex
  ```
  Does `git reset --hard origin/main` (in `/opt/plan-b-siem`) + `docker compose pull` + `up -d`. **Named volumes preserved** (OpenSearch data, users.db/TOTP, /data). Recreates containers — **after every update, desktops' NXLog may need a reconnect** (see §5).
- Wait for the **`UPDATE COMPLETE - data preserved`** banner + the prompt to return.

---

## 4. Log sources

### 4a. SentinelOne (EDR) — pulled, not pushed
Portal seals the S1 creds → checker writes `/data/s1_integration.json` → `plan-b-syslog` poller hits S1 `/threats`+`/activities` (5-min interval, 15-min lookback; **no historical backfill**).
- **Verify:** `docker logs plan-b-syslog | Select-String "\[s1\]"` → `[s1] cycle: written=N duplicates=N failed=0`.
- `failed=0` = poller healthy. `written=0` = **no new S1 events in that window — normal; EDR is bursty.** A quiet hour is not a fault.

### 4b. Windows via NXLog (TCP 1514, JSON)
NXLog config **must**: `Exec to_json(); $raw_event = $raw_event + "\n"` (the `\n` is the record delimiter the box's TCP handler splits on — **without it nothing parses**), `om_tcp` to `box:1514`. File must be **config-only** (a pasted "Replace" prose line at line 1 = `Invalid keyword` start failure), **UTF-8 no BOM, straight quotes**.

- **File server (file-access):** GPO/Local-Sec-Policy → Object Access → **Audit File System** + **Audit Detailed File Share** (Success+Failure) + "Force subcategory settings"; **SACLs on the target folder(s) only** (no SACL = no events). NXLog `im_msvistalog` QueryXML filtered to **4663/4660/4670/5140/5145**. `parsers/windows.js` → `file_path`, `src_user`, and for **5145** the **workstation `src_ip`**. (Workstation→share access is logged on the SERVER, so for server/share files you only configure the server.)
- **Desktops (endpoint):** NXLog QueryXML filtered to **4624/4625/4634/4647/4648/4672/4688/4720-4726/4728/4732/4740/1102** (+ System **7045**). `windows.js` → `login`+`logon_type`, `process_create`+`command_line`, account/lockout/service actions, and `source=host` (the machine name — that's how it appears in the dashboard **Sources** list). **4688 needs "Audit Process Creation" enabled** (+ the command-line GPO) or it's silent.

### 4c. Firewall (syslog UDP 514)
Pluggable multi-vendor parser stack (`parsers/`): **Check Point** (CEF/LEEF/key=value Log-Exporter **+ SMB/Quantum Spark `key="value"`**), **Fortinet**, **Palo Alto**, Cisco, Aruba, DNS, CEF/LEEF/JSON, generic fallback.
- **Check Point Quantum Spark (SMB, e.g. the 1570):** WebUI → **Logs & Monitoring → External Log Servers → Syslog Servers** → Protocol **UDP**, IP = box, Port **514**, native format (no CEF needed). Needs Track=Log on the rules + traffic.
- **⚠ CRITICAL — the WSL UDP relay (§5).** `netsh portproxy` is **TCP-only**, so firewall UDP 514 reaches the host but is **dropped before WSL** unless the relay is running. This is the single biggest gotcha on a WSL box.

---

## 5. Troubleshooting playbook

| Symptom | Root cause | Fix |
|---|---|---|
| **No firewall/UDP logs; `[stats] UDP: 0` while TCP climbs** | `netsh portproxy` is TCP-only — UDP 514 not forwarded into WSL | Install the relay: `irm .../main/udp-relay-install.ps1 \| iex`. Check `C:\PlanB-SIEM\udp-relay.log` for `Bound UDP 514` + `WSL IP -> 172.30.x` |
| **Relay log: `FATAL/bind attempt failed: Only one usage of each socket address`** | a stale relay still holds UDP 514 | `Stop-Process -Id (Get-NetUDPEndpoint -LocalPort 514).OwningProcess -Force` — the relay retries the bind and recovers |
| **Relay log: `WSL IP -> Running`** (forwards nowhere) | SYSTEM context can't run `wsl … hostname -I` | (fixed) relay reads the WSL IP from the portproxy table; re-run `udp-relay-install.ps1` |
| **Firewall logs land but `device_vendor:aruba` / `null`** | parser didn't recognize the format | Quantum Spark `key="value"` now handled; for a new vendor format, add a parser + dispatch entry |
| **A desktop goes quiet after `update.ps1`** | container recreate dropped the NXLog TCP session | on the desktop: `net stop nxlog` / `net start nxlog` |
| **S1 `authenticated=False`, no AI/S1/updates** | missing `AWAITING_INSTALL` slot (often cascade-deleted) | create the slot in the portal → `docker restart plan-b-license-checker` → expect `authenticated=True / bootstrapped=True` |
| **AI features disabled** | `ai_tier=NONE` | set `ai_tier` in the portal/DB → restart checker → expect `AI key saved (tier=…)` in checker logs |
| **AI answers but "couldn't run the search"** (`לא הצלחתי להריץ את החיפוש`) | model wrote a malformed OpenSearch query; route gives up (`api/ai/chat` ~L257) | **OPEN** — add 1 auto-retry feeding the OS error back to the model (or switch to Anthropic tool-use) |

---

## 6. Verification commands

> **Mike's box = PowerShell 5 over RDP.** Rules: **no `&&`** (separate lines); **no `&` in a URL** (it gets swallowed — use single-param `?q=…`); **avoid long one-liners** (they mangle/duplicate on paste — prefer `irm <short-url> | iex`); run **one command at a time**.

```powershell
# containers
wsl -d PlanB-SIEM -u root -- docker ps --format "table {{.Names}}\t{{.Status}}"
# total log count
wsl -d PlanB-SIEM -u root -- docker exec plan-b-opensearch curl -s "http://localhost:9200/logs-*/_count"
# count by vendor (single ?q= param, NO &)
wsl -d PlanB-SIEM -u root -- docker exec plan-b-opensearch curl -s "http://localhost:9200/logs-*/_count?q=device_vendor:checkpoint"
# S1 poller health
wsl -d PlanB-SIEM -u root -- docker logs --tail 20 plan-b-syslog | Select-String "\[s1\]"
# syslog intake stats (UDP/TCP counters)
wsl -d PlanB-SIEM -u root -- docker logs --tail 15 plan-b-syslog
# UDP relay status
Get-Content C:\PlanB-SIEM\udp-relay.log -Tail 6
# AI key delivery
wsl -d PlanB-SIEM -u root -- docker logs --tail 40 plan-b-license-checker | Select-String "AI"
# AI search error (after triggering a failing query in the dashboard)
wsl -d PlanB-SIEM -u root -- docker logs --tail 30 plan-b-dashboard
```

---

## 7. Deploy rules (per repo)

- **`siem-docker` (this repo, on-prem stack):** push **straight to `main`** (Mike has no separate test env for it) — surface the change + get his go first. A push to `main` rebuilds the ghcr `:v2` images; the box pulls via `update.ps1`.
- **`pbsiem` (cloud portal/MDR):** **dev-first**; `main` is protected → feature branch → PR → `ci/CI` green → `gh pr merge`. Merging to `main` **auto-deploys** prod on Vercel. Prisma changes via `prisma db push` (apply additive schema *before* the code deploy).
