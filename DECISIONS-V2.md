# SIEM On-Prem v2 — Architecture Decisions & Reasoning

> This document captures every architectural decision made during the v2 planning session (April 7, 2026). It explains **what** was decided, **why**, and **what alternatives were rejected**.

---

## 1. Drop Graylog Entirely

**Decision:** Remove Graylog and MongoDB from the on-prem stack.

**Why:**
- Graylog's UI is clunky and hard to customize — not suitable for client-facing demos
- Graylog + MongoDB consume ~2-4GB RAM unnecessarily
- Graylog is a Java application with complex configuration (password secrets, Java truststore, pipeline rules)
- MongoDB exists solely because Graylog requires it — we have no other use for it
- Every Graylog upgrade is a risk (config format changes, breaking changes, license changes)
- We cannot control settings from our own UI when Graylog owns the configuration
- Graylog's "pipeline rules" (log parsing, enrichment, normalization, routing) can be done more simply in our own Node.js syslog receiver code

**Alternatives rejected:**
- *Keep Graylog hidden (headless, no UI exposed):* Still adds 2 containers, 2-4GB RAM, and a dependency we don't control. Partial control is worse than full control.
- *Drop Graylog + Drop OpenSearch (use ClickHouse):* Too radical — ClickHouse is unfamiliar territory, and OpenSearch works well for our use case. Risk outweighs the footprint savings.

**Impact:**
- Stack goes from 5 containers to 4
- RAM requirement drops from 8GB to 4GB minimum
- Deployment is faster and simpler
- We own 100% of the code

---

## 2. v2 Stack Architecture

**Decision:** 4-container stack:
1. `plansb-opensearch` — OpenSearch 2.18 (log storage, unchanged)
2. `plansb-syslog` — Node.js syslog receiver (adapted from cloud)
3. `plansb-dashboard` — Next.js branded dashboard (new)
4. `plansb-license` — License checker (updated targets)

**Why:**
- OpenSearch is proven, already in production, handles search/aggregation well
- The cloud syslog receiver (`cloud-siem-receiver/server.js`, ~340 lines) already handles UDP/TCP, RFC 3164/5424/FortiGate parsing, and direct OpenSearch writes — we just containerize it
- Next.js matches our cloud SIEM tech stack — same components, same patterns, team already knows it
- License checker already exists and works — just needs target container name changes

**Container naming:** Prefix `plansb-` = Plan-B Systems (consistent with v1 naming convention: plansb-graylog, plansb-opensearch, etc.)

---

## 3. Branch Strategy — v1/v2 Coexistence

**Decision:** `v2` branch in siem-docker repo. `main` stays as v1.

**Why:**
- Existing v1 clients (like PlaySmart) must not be affected
- Both versions must be deployable at any time via one-liner:
  - v1: `irm https://raw.githubusercontent.com/plan-b-systems/siem-docker/main/install.ps1 | iex`
  - v2: `irm https://raw.githubusercontent.com/plan-b-systems/siem-docker/v2/install.ps1 | iex`
- When v2 is stable and tested, it merges to `main` and v1 gets tagged as `v1`

**Rule:** No changes to `main` branch until Mike specifically approves. v2 development happens exclusively on the `v2` branch.

---

## 4. Syslog Receiver — Adapt from Cloud

**Decision:** Copy and adapt `cloud-siem-receiver/server.js` into `siem-docker/syslog-receiver/`.

**What changes from cloud version:**
- Remove the allowlist/API mechanism (on-prem = trusted network, single client)
- Client ID and name come from environment variables (config.env), not from API lookup
- OpenSearch URL changes to `http://opensearch:9200` (Docker internal network)
- Add OpenSearch ISM (Index State Management) policy creation on startup for automated retention/rotation
- Containerize with Dockerfile (Node.js 22-alpine)

**What stays the same:**
- UDP:514 + TCP:1514 dual-stack reception
- RFC 3164, RFC 5424, and FortiGate key=value parsing
- Monthly index rotation (`logs-{client_id}-YYYY.MM`)
- OpenSearch index template with optimized mappings
- All ~340 lines of battle-tested parsing code

**Why not write from scratch:** The cloud receiver is production-proven, handles edge cases (buffer overflow, malformed messages, FortiGate quirks). Rewriting would introduce bugs for no benefit.

---

## 5. Dashboard — Settings Storage in OpenSearch

**Decision:** Store dashboard settings in an OpenSearch index (`plansb-settings`) with a single document.

**Why:**
- OpenSearch is already running — no additional dependency
- A single JSON document is all we need (language, timezone, retention, password hash, theme)
- Simple GET/PUT to `plansb-settings/_doc/config`
- No SQLite (adds a file mount and migration complexity)
- No PostgreSQL (way overkill for a single config document)
- No file-based config (harder to update from the UI, permission issues in containers)

**Settings schema:**
```json
{
  "language": "he",
  "timezone": "Asia/Jerusalem",
  "retention_days": 730,
  "client_name": "from config.env",
  "client_id": "from config.env",
  "dashboard_password_hash": "bcrypt hash",
  "theme": "dark"
}
```

---

## 6. Dashboard Auth — Simple Password + JWT

**Decision:** Single password authentication with bcrypt hash + HTTP-only JWT cookie.

**Why:**
- On-prem SIEM doesn't need user management — one admin password is enough
- Password is set during `install.sh` (same UX as v1 Graylog admin password)
- bcrypt hash stored in config.env and seeded into OpenSearch settings
- JWT cookie (signed with secret from config.env) — expires after 24h
- Middleware checks JWT on all routes except `/login`
- No NextAuth, no Prisma, no database — lightweight and self-contained

**Alternatives rejected:**
- *NextAuth + Prisma:* Massive overkill for single-password on-prem auth. Adds PostgreSQL dependency.
- *Basic HTTP auth:* No session persistence, poor UX (browser popup)
- *No auth:* Unacceptable — SIEM dashboard must be protected even on internal networks

---

## 7. Index Retention — OpenSearch ISM Policy

**Decision:** Use OpenSearch ISM (Index State Management) for automated index retention and rotation.

**Why:**
- This was previously handled by Graylog's retention settings
- OpenSearch ISM is the native replacement — same capability, no Graylog needed
- The syslog receiver creates/updates the ISM policy on every startup (self-healing)
- Policy config: monthly indices, delete after `RETENTION_DAYS` (default 730 for Israeli privacy regulations)
- If retention days change in settings UI, the dashboard API updates both the settings doc and the ISM policy

**Retention requirement:** 730 days (2 years) per Israeli privacy regulation (Amendment 13). This is not configurable below the legal minimum.

---

## 8. Bilingual Support — HE/EN

**Decision:** Full Hebrew and English support with user-selectable language in settings.

**Why:**
- Israeli clients need Hebrew (RTL) UI
- International clients / English-speaking IT staff need English
- Language preference stored in OpenSearch settings, persisted across sessions
- RTL layout toggles automatically based on language selection
- Translation implemented as React context + dictionary files (no i18next library — too heavy for ~200 strings)

---

## 9. AI Chat — Direct to Claude API with Rotated Key

**Decision:** On-prem AI chat calls Claude API (`api.anthropic.com`) directly. API key is delivered daily by the license checker.

**Why the proxy approach was rejected:**
- A cloud proxy (`siemsys.plan-b.systems/api/ai/proxy`) would be a single point of failure
- If our cloud goes down, every on-prem client's AI stops working
- This contradicts the core value of on-prem: independence from external services
- Added latency (~200ms per request) for no real benefit

**How the rotated key approach works:**
1. License checker calls `siemsys.plan-b.systems/api/license/check` daily (already does this)
2. If client has an active AI tier (STARTER/PRO/UNLIMITED), the response includes:
   - A short-lived Anthropic API key (unique per client, rotated daily)
   - Daily token budget
3. Dashboard holds the key in memory only — never written to disk
4. Dashboard calls `api.anthropic.com` directly with that key
5. Dashboard enforces budget locally — stops queries when daily budget exhausted
6. Dashboard reports usage back to siemsys for billing

**Security controls:**
- Per-client API key with spend limits set on Anthropic's side
- Key rotates daily — compromised key is only valid for hours
- Key never written to disk — only in container memory
- If license expires or AI tier = NONE, key is deleted from memory
- We monitor usage on Anthropic's dashboard — anomalies trigger revocation

**Business model:** Clients purchase AI token packages through the Plan-B cloud portal (siemsys). We buy from Anthropic at cost and sell with margin. The client never manages API keys directly.

---

## 10. Dashboard Build Strategy

**Decision:** Build dashboard Docker image from Dockerfile at deploy time (like the license-checker).

**Why:**
- No Docker registry needed — deployment is self-contained
- `install.sh` runs `docker compose build` which builds both dashboard and syslog containers
- Multi-stage Dockerfile: Stage 1 installs deps + builds Next.js. Stage 2 copies standalone output into minimal Node.js alpine image (~150MB final).
- Same pattern as the existing license-checker container

**Alternatives rejected:**
- *Pre-built images on Docker Hub:* Requires maintaining a registry, version tags, and client machines need internet access to Docker Hub during deployment. Adds complexity.
- *Pulling from GitHub Container Registry:* Same issues plus GHCR auth complexity.

---

## 11. Dashboard Design — Dark Theme, Plan-B Branded

**Decision:** Dark theme primary with Plan-B branding throughout.

**Logo assets:**
- Dark backgrounds: `planB-logo-negativ1-final.png` (white PLAN text + cyan B)
- Compact header: `planB-logo-negativ1-160x53.png`
- Light backgrounds (login page): `planB-logo-final.png` (blue PLAN text)

**Pages:**
1. **Overview** — Log volume timeline, severity pie chart, top sources, top applications
2. **Threats** — Filter emergency/alert/critical/error, attack timeline, source correlation
3. **Forensics** — Full log viewer with search, time range, severity filter, pagination, CSV export
4. **Sources** — Device inventory, per-source stats, last-seen timestamp, health indicator
5. **Settings** — Language, timezone, retention, client info, OpenSearch status, password change

**Tech stack:** Next.js 14 (standalone output), Tailwind CSS, Lucide icons — matches cloud SIEM for code reuse.

---

## 12. Deployment Simplicity

**Decision:** One-liner deployment, same as v1.

**Why:** Client site deployment must be quick. The technician runs one PowerShell command, answers 5 prompts (client name, ID, IP, password, retention), and waits 10 minutes. No manual Docker knowledge required.

**v2 simplifications over v1:**
- No Graylog password secret generation (96-char random)
- No MongoDB password generation
- No Java truststore extraction and CA cert import
- No Graylog REST API configuration (inputs, index sets)
- Lower RAM requirement (4GB vs 8GB)
- Fewer containers to health-check

---

## 13. Encrypted On-Prem ↔ Cloud Communication

**Decision:** All on-prem to cloud API communication must be authenticated and encrypted beyond basic HTTPS.

**Why:**
- The license check response carries an Anthropic API key — if intercepted, it could be abused
- Client IDs and usage data are business-sensitive
- Basic HTTPS protects transport but doesn't authenticate the client — anyone could call the license API with a guessed client_id

**Implementation:**
1. **Client secret:** Each on-prem installation gets a unique secret (generated during `install.sh`, registered on siemsys cloud portal). Every API call includes this as a bearer token.
2. **Encrypted AI key delivery:** The Anthropic API key in the license response is encrypted with the client secret. Only the correct on-prem installation can decrypt it.
3. **Certificate pinning (optional):** Pin siemsys TLS certificate to prevent MITM with rogue CA.
4. **Replay protection:** Include timestamp + nonce in requests, cloud rejects stale requests.

**Flow:**
```
On-Prem                                    Cloud (siemsys)
   │                                           │
   │  POST /api/license/check                  │
   │  Authorization: Bearer {client_secret}    │
   │  Body: { client_id, timestamp, nonce }    │
   │  ────────────────────────────────────►     │
   │                                           │  Validate secret
   │                                           │  Check subscription
   │                                           │  Encrypt AI key
   │  ◄────────────────────────────────────    │
   │  { status, ai_key_encrypted, budget }     │
   │                                           │
   │  Decrypt ai_key with client_secret        │
   │  Store in memory only                     │
```

---

## Decision Log

| # | Decision | Date | Status |
|---|----------|------|--------|
| 1 | Drop Graylog + MongoDB | 2026-04-07 | Approved |
| 2 | 4-container v2 stack | 2026-04-07 | Approved |
| 3 | v2 branch, v1 on main | 2026-04-07 | Approved |
| 4 | Adapt cloud syslog receiver | 2026-04-07 | Approved |
| 5 | Settings in OpenSearch | 2026-04-07 | Approved |
| 6 | Password + JWT auth | 2026-04-07 | Approved |
| 7 | OpenSearch ISM for retention | 2026-04-07 | Approved |
| 8 | HE/EN bilingual | 2026-04-07 | Approved |
| 9 | Direct Claude API + rotated key | 2026-04-07 | Approved |
| 10 | Build images at deploy time | 2026-04-07 | Approved |
| 11 | Dark theme, Plan-B branded | 2026-04-07 | Approved |
| 12 | One-liner deployment | 2026-04-07 | Approved |
| 13 | Encrypted on-prem↔cloud API | 2026-04-07 | Approved |
