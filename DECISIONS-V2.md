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
1. `plan-b-opensearch` — OpenSearch 2.18 (log storage, unchanged)
2. `plan-b-syslog` — Node.js syslog receiver (adapted from cloud)
3. `plan-b-dashboard` — Next.js branded dashboard (new)
4. `plan-b-license` — License checker (updated targets)

**Why:**
- OpenSearch is proven, already in production, handles search/aggregation well
- The cloud syslog receiver (`cloud-siem-receiver/server.js`, ~340 lines) already handles UDP/TCP, RFC 3164/5424/FortiGate parsing, and direct OpenSearch writes — we just containerize it
- Next.js matches our cloud SIEM tech stack — same components, same patterns, team already knows it
- License checker already exists and works — just needs target container name changes

**Container naming:** Prefix `plan-b-` = Plan-B Systems (consistent with v1 naming convention: plan-b-graylog, plan-b-opensearch, etc.)

---

## 3. Branch Strategy — v2.1 on Main

**Current status as of 2026-05-06:** v1 is retired. v2.1 is the supported on-prem stack and is deployed from the `main` branch.

**Original decision, superseded:** `v2` branch in siem-docker repo. `main` stays as v1.

**Why:**
- Existing v1 clients (like PlaySmart) must not be affected
- Both versions must be deployable at any time via one-liner:
  - v1: `irm https://raw.githubusercontent.com/plan-b-systems/siem-docker/main/install.ps1 | iex`
  - v2: `irm https://raw.githubusercontent.com/plan-b-systems/siem-docker/main/install.ps1 | iex`
- When v2 is stable and tested, it merges to `main` and v1 gets tagged as `v1`

**Current rule:** public one-line installers use `main`. Deployment scripts must not fetch, checkout, pull, or clone the retired `v2` branch.

**Original rule, superseded:** No changes to `main` branch until Mike specifically approves. v2 development happens exclusively on the `v2` branch.

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

**Decision:** Store dashboard settings in an OpenSearch index (`plan-b-settings`) with a single document.

**Why:**
- OpenSearch is already running — no additional dependency
- A single JSON document is all we need (language, timezone, retention, password hash, theme)
- Simple GET/PUT to `plan-b-settings/_doc/config`
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

## 13. Encrypted On-Prem ↔ Cloud Communication — ed25519/X25519 keypair model

**Status as of 2026-04-23**: **shipped**. Replaced the shared-secret sketch originally drafted in this section (which was only half-implemented) with an asymmetric keypair model that provides zero-plaintext-transit. See `pbsiem/docs/on-prem-secret-lifecycle.md` for the authoritative spec.

**Short version of the shipped design:**
- On first boot the `plan-b-license-checker` container generates an ed25519 keypair (signing) + X25519 keypair (encryption) under `/data/plan-b-*-private.pem`. Private keys never leave.
- Bootstrap call to `/api/license/check` carries the two public keys + an ed25519 signature over `"bootstrap:<client_id>:<ts>:<nonce>"`. Portal verifies, stores public keys on the `OnPremInstallation` row, records source IP, responds with sealed-box-encrypted ANTHROPIC_API_KEY.
- Daily calls carry only a signature (no payload), portal verifies against stored public key, responds with AI key encrypted to X25519 public.
- Admin can trigger rotation — on-prem generates new pair on next call and sends proof of possession of BOTH old and new. No secret transits plaintext at any time.
- IP mismatch → 7-day grace (reuses the existing GRACE_PERIOD state machine) then EXPIRED.

**Original section text (for historical reference only — describes pre-implementation intent, superseded above):**

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
| 3 | v2.1 deployed from main; retired v2 branch references removed | 2026-05-06 | Supersedes original v1/main + v2 branch decision |
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
| 14 | API key rotation process | 2026-04-07 | Approved |
| 15 | Multi-user auth, tier 2 (SQLite + TOTP MFA + lockout + audit + self-service reset) | 2026-04-22 | Approved |
| 16 | SentinelOne (EDR) ingestion — built-in, portal-delivered credentials | 2026-06-21 | Approved |

---

## 14. Anthropic API Key Rotation

**Decision:** Single organizational API key, rotated manually via Anthropic console, propagated automatically to all on-prem clients.

**Why:**
- Anthropic doesn't offer per-client API keys or an API for key management
- One key per organization is the only option
- On-prem clients must never store a permanent key — they receive it encrypted daily

**Rotation process:**
1. Create new key on console.anthropic.com
2. Update `ANTHROPIC_API_KEY` in Vercel env vars (siemsys production + dev)
3. All on-prem clients automatically get the new encrypted key on next daily license check (within 24h)
4. After 48h (all clients rotated), delete the old key on console.anthropic.com

**Automatic propagation:** The license check API reads `ANTHROPIC_API_KEY` from its environment on every request. When the env var changes (Vercel redeploy), all subsequent license checks return the new key encrypted. No on-prem changes needed.

**Grace period:** If a client misses the daily check (network down), the old key continues working until step 4 (old key deletion). The 7-day grace period in the license checker covers temporary outages.

**Per-client controls (all from siemsys admin, no on-prem access needed):**
- **Enable/disable AI:** Set `ai_tier` to NONE → key file deleted on next check
- **Change budget:** Set `ai_tier` (STARTER=50/day, PRO=200/day, UNLIMITED=9999/day)
- **Kill switch:** Revoke `client_secret` → license check fails auth → AI stops immediately
- **Usage monitoring:** AiUsage table tracks queries per client per month

**Cannot automate (Anthropic limitation):**
- Key creation (manual on console.anthropic.com)
- Per-key spend limits (workspace-level only)
- Per-key usage tracking (all keys share one dashboard)

---

## 15. Multi-user auth (tier 2)

**Decision (2026-04-22):** Replace the single shared `DASHBOARD_PASSWORD` with a named-user system (SQLite + bcrypt), TOTP MFA mandatory for every user, 5-fail 15-min account lockout, password history + policy, JWT sessions with DB-backed revocation + 60-min idle / 24-h absolute timeout, audit log, and self-service password reset via email.

**Why:**
- Enterprise customers won't accept "one shared admin password per site" — it's a failed finding in every security questionnaire.
- A tier-2 design (named accounts + MFA + lockout + audit) meets OWASP ASVS L2 without the complexity of SSO/SCIM.

**Storage:** `dashboard-data` docker volume mounted at `/auth-data`, SQLite `users.db` opened by the dashboard container in WAL mode. Separate from `license-data` (which stays read-only for the dashboard and read-write for license-checker). No cloud dependency — the on-prem install remains self-sufficient.

**Bootstrap:** On first start the dashboard seeds a single `admin` user whose password is the bcrypt hash of the installer-time `DASHBOARD_PASSWORD`. `must_change_password = 1` + `mfa_enrolled = 0` are set so the admin is funnelled through `/change-password` → `/enroll-mfa` before reaching any dashboard page. No behaviour change for sites that haven't migrated — the installer already writes `DASHBOARD_PASSWORD_HASH` and the seed reuses it verbatim.

**Emergency access:** `docker exec plan-b-dashboard node scripts/reset-admin.js <new-pw>` resets the admin, clears MFA, and requires a change-on-next-login. A shell wrapper `scripts/reset-admin.sh` lives in the repo root for convenience.

**Password policy (enforced in `src/lib/auth-password.ts`):**
- ≥12 characters, with upper + lower + digit
- Cannot contain the username
- Cannot match any of the last 5 hashes
- bcrypt cost factor 12

**Lockout:** 5 consecutive failed password or MFA attempts → 15-minute lockout. Admin can unlock from `/admin/users`.

**MFA:** RFC 6238 TOTP (30 s step, ±1 step drift tolerance) via `otplib`. Secret generated server-side, shown to the user once as a QR + manually-copyable string, confirmed with a 6-digit code before `mfa_enrolled` flips to 1. Re-enrolment post-activation requires an admin "Clear MFA" — a hijacked session cannot rebind MFA to the attacker's device.

**Sessions:** JWT (jose HS256) carrying `{sub, jti}`. `jti` maps to a `sessions` row with `issued_at / expires_at / idle_expires_at`. Every API request refreshes `idle_expires_at`; 60 min idle or 24 h absolute wins first. Admin action "Revoke sessions" sets `revoked_at` — the next request from that cookie is denied. Password change and reset revoke all sessions.

**Audit log:** Every authentication event, every admin mutation (user create / update / password reset / clear MFA / unlock / revoke / delete) writes a row to `audit_log` with actor, IP, user-agent, success flag, and free-form message. Viewable by admins at `/admin/audit`.

**Self-service reset:** `/forgot-password` accepts username or email, always 200s (no enumeration), writes a hashed token with 30-min TTL. If SMTP is configured AND the user has an email on file, the reset link is emailed. Otherwise the link is logged to the dashboard container's stdout so an admin can retrieve it via `docker logs`.

**Middleware:** Edge-runtime middleware only verifies the JWT signature + expiry (no DB access — better-sqlite3 isn't Edge-compatible). Deeper checks (session revocation, idle timeout, user state, role) happen in the dashboard layout's server component and in every `requireUser()` / `requireAdmin()` call from API routes.

**Forced-flow enforcement:** The `(dashboard)/` layout server component calls `requireUser()` → redirects to `/change-password` if `must_change_password`, else to `/enroll-mfa` if `!mfa_enrolled`. Admin-only pages live under `(dashboard)/admin/` with an additional `requireAdmin()` in the nested layout.

**Cookie hardening:** `httpOnly`, `sameSite=lax`. `secure=true` only when `COOKIE_SECURE=1` — on-prem installs typically start over plain HTTP and add TLS later via reverse proxy.

**Files added:**
- `dashboard/src/lib/auth-db.ts` (schema + migrations)
- `dashboard/src/lib/auth-password.ts` (policy, hash, history)
- `dashboard/src/lib/auth-totp.ts` (TOTP + QR)
- `dashboard/src/lib/auth-session.ts` (JWT + DB session model)
- `dashboard/src/lib/auth-audit.ts`
- `dashboard/src/lib/auth-email.ts` (nodemailer, optional)
- `dashboard/src/lib/auth-users.ts` (CRUD + lockout + auth)
- `dashboard/src/lib/auth-bootstrap.ts` (seed admin from legacy hash)
- `dashboard/src/lib/auth-require.ts` (route guards)
- `dashboard/src/app/api/auth/{login,verify-mfa,logout,me,change-password,enroll-mfa,confirm-mfa,forgot-password,reset-password}/route.ts`
- `dashboard/src/app/api/admin/users/...` (list, create, get, patch, delete, reset-password, clear-mfa, unlock, revoke-sessions)
- `dashboard/src/app/api/admin/audit/route.ts`
- `dashboard/src/app/{login,change-password,enroll-mfa,forgot-password,reset-password}/page.tsx`
- `dashboard/src/app/(dashboard)/admin/{users,audit}/page.tsx` + `admin/layout.tsx`
- `dashboard/scripts/reset-admin.js` + `scripts/reset-admin.sh` (emergency CLI)

**Supersedes decision 6** ("Password + JWT auth") — JWT is retained but is no longer the whole story; the DB is now the source of truth for session liveness.

---

## 16. SentinelOne (EDR) Ingestion — built-in, portal-delivered credentials

**Decision (2026-06-21):** Add SentinelOne API ingestion to the on-prem stack as
a built-in capability of the existing ingestion service (the syslog receiver),
NOT a separate puller container. Credentials are delivered from the cloud portal
via the license-checker (sealed to the install's X25519 key) — never entered or
stored on the box in a settings UI.

**Why:**
- Product parity with Cloud SIEM (which pulls S1 via its `edr-puller`), as one
  closed product with all capabilities included — no bolt-on container.
- Portal-delivery removes both cloud-couplings the cloud puller has: the box
  needs neither `MDR_ENCRYPTION_KEY` nor a multi-tenant DB lookup. The portal
  does the lookup + AES-GCM decrypt and re-seals to the install's key; the box
  just reads a JSON file and polls.
- The MSP manages the integration centrally in the portal (impersonate → MDR →
  Integrations), matching how they manage everything else for the client.

**Alternatives rejected:**
- *Separate edr-puller container on-prem:* fragments the product; the call was
  one closed stack with every capability built in.
- *Enter the token in the on-prem dashboard:* puts a plaintext cloud credential
  on the customer box and duplicates portal functionality. Portal-delivery keeps
  the secret off the box.

**Implementation:** `syslog-receiver/server.js` (poll loop + normalizer ported
from the cloud edr-puller, `_create` dedupe, independent per-feed pulls),
`license-checker/checker.py` (sealed-box decrypt → `/data/s1_integration.json`),
compose mounts `license-data:/data:ro` on the ingestion service. Pairs with
pbsiem `/api/license/check` delivering `s1_integration_sealed`. **M365 ingestion
is the planned next capability** (heavier: needs an app-only OAuth flow rather
than the portal's interactive per-tenant consent).
