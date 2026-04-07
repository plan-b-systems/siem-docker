import { NextResponse } from 'next/server'
import { config } from '@/lib/config'

export async function GET() {
  const fs = require('fs')

  // Read license state from shared volume
  const stateFile = '/data/license_state.json'
  const aiKeyFile = process.env.AI_KEY_FILE || '/data/ai_key.json'

  let license: Record<string, unknown> = {
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
  } catch { /* file not found or invalid */ }

  // AI tier info
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
  } catch {
    license.ai_tier = 'NONE'
    license.ai_daily_budget = 0
  }

  return NextResponse.json(license)
}
