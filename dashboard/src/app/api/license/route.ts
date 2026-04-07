import { NextResponse } from 'next/server'
import { config } from '@/lib/config'

export const dynamic = 'force-dynamic'

export async function GET() {
  // Use require('node:fs') to avoid Next.js tree-shaking the module
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const fs = require('node:fs')

  const stateFile = '/data/license_state.json'
  const aiKeyFile = process.env.AI_KEY_FILE || '/data/ai_key.json'

  const license: Record<string, unknown> = {
    status: 'UNKNOWN',
    last_check: null,
    active: false,
    expires: null,
    client_id: config.clientId,
    client_name: config.clientName,
  }

  try {
    if (fs.existsSync(stateFile)) {
      const state = JSON.parse(fs.readFileSync(stateFile, 'utf8'))
      license.status = state.status || 'UNKNOWN'
      license.last_check = state.last_check
      license.active = state.last_result?.active ?? false
      license.expires = state.last_result?.expires
      license.services_stopped = state.services_stopped
      license.install_time = state.install_time
    }
  } catch (err) {
    console.error('[license] State file error:', err)
  }

  try {
    if (fs.existsSync(aiKeyFile)) {
      const ai = JSON.parse(fs.readFileSync(aiKeyFile, 'utf8'))
      license.ai_tier = ai.ai_tier || 'NONE'
      license.ai_daily_budget = ai.daily_budget || 0
      license.ai_updated = ai.updated_at
    } else {
      license.ai_tier = 'NONE'
      license.ai_daily_budget = 0
    }
  } catch (err) {
    console.error('[license] AI key file error:', err)
    license.ai_tier = 'NONE'
    license.ai_daily_budget = 0
  }

  return NextResponse.json(license)
}
