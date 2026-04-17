import { NextResponse } from 'next/server'
import { config } from '@/lib/config'

const OS_URL = config.opensearchUrl
const SETTINGS_INDEX = 'plan-b-settings'
const DOC_ID = 'config'

async function osRequest(method: string, path: string, body?: unknown) {
  const res = await fetch(`${OS_URL}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
    cache: 'no-store',
  })
  return { ok: res.ok, status: res.status, data: res.ok ? await res.json() : null }
}

export async function GET() {
  try {
    // Try to get existing settings
    const { ok, data } = await osRequest('GET', `/${SETTINGS_INDEX}/_doc/${DOC_ID}`)

    if (ok && data?._source) {
      return NextResponse.json(data._source)
    }

    // Settings don't exist — seed defaults
    const defaults = {
      language: 'he',
      timezone: config.timezone,
      retention_days: config.retentionDays,
      client_name: config.clientName,
      client_id: config.clientId,
      theme: 'dark',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    }

    await osRequest('PUT', `/${SETTINGS_INDEX}/_doc/${DOC_ID}`, defaults)
    return NextResponse.json(defaults)
  } catch (error) {
    console.error('Settings GET error:', error)
    // Return defaults if OpenSearch is unreachable
    return NextResponse.json({
      language: 'he',
      timezone: config.timezone,
      retention_days: config.retentionDays,
      client_name: config.clientName,
      client_id: config.clientId,
      theme: 'dark',
      opensearch_status: 'disconnected',
    })
  }
}

export async function PUT(req: Request) {
  try {
    const body = await req.json()
    const update = {
      ...body,
      client_name: config.clientName,
      client_id: config.clientId,
      updated_at: new Date().toISOString(),
    }

    await osRequest('PUT', `/${SETTINGS_INDEX}/_doc/${DOC_ID}`, update)
    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Settings PUT error:', error)
    return NextResponse.json({ error: 'Failed to save settings' }, { status: 500 })
  }
}
