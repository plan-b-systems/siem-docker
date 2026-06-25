import { NextResponse } from 'next/server'

export const dynamic = 'force-dynamic'

// GET /api/portal-status
// Reads the read-only /data mount written by the license-checker. Prefers the
// dedicated portal_status.json; falls back to license_state.json for boxes
// whose license-checker predates that file. Used by <PortalBanner /> to render
// the "not connected to portal" alarm when this install has not bootstrapped.
export async function GET() {
  // Use require('node:fs') to avoid Next.js tree-shaking the module (same
  // pattern as /api/license).
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { existsSync, readFileSync } = require('node:fs')

  const out: Record<string, unknown> = {
    bootstrapped: null,
    authenticated: null,
    license_status: null,
    last_check: null,
    failed_bootstrap_count: 0,
    last_error: null,
    source: 'none',
  }

  try {
    const f = process.env.PORTAL_STATUS_FILE || '/data/portal_status.json'
    if (existsSync(f)) {
      Object.assign(out, JSON.parse(readFileSync(f, 'utf8')))
      out.source = 'portal_status'
      return NextResponse.json(out)
    }
  } catch (err) {
    console.error('[portal-status] portal_status.json error:', err)
    // fall through to legacy
  }

  // Legacy fallback: license_state.json has bootstrapped + status + last_check.
  try {
    const sf = process.env.STATE_FILE || '/data/license_state.json'
    if (existsSync(sf)) {
      const s = JSON.parse(readFileSync(sf, 'utf8'))
      out.bootstrapped = !!s.bootstrapped
      out.authenticated = s.authenticated ?? null
      out.license_status = s.status ?? null
      out.last_check = s.last_check ?? null
      out.failed_bootstrap_count = s.failed_bootstrap_count ?? 0
      out.source = 'license_state'
    }
  } catch (err) {
    console.error('[portal-status] license_state.json error:', err)
  }

  return NextResponse.json(out)
}
