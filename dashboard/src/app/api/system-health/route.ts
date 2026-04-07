import { NextResponse } from 'next/server'
import { osQuery, getIndexPattern } from '@/lib/opensearch'
import { config } from '@/lib/config'
import { existsSync, readFileSync } from 'fs'

export async function GET() {
  const health: Record<string, unknown> = {
    client_id: config.clientId,
    client_name: config.clientName,
    timestamp: new Date().toISOString(),
  }

  // OpenSearch cluster health
  try {
    const cluster = await osQuery('GET', '/_cluster/health')
    health.os_cluster = cluster.status
    health.os_shards_active = cluster.active_shards
    health.os_shards_unassigned = cluster.unassigned_shards
  } catch {
    health.os_cluster = 'unreachable'
  }

  // OpenSearch index stats
  try {
    const stats = await osQuery('GET', `/${getIndexPattern()}/_stats/store,docs`)
    const all = stats._all?.primaries || {}
    health.os_doc_count = all.docs?.count || 0
    health.os_store_bytes = all.store?.size_in_bytes || 0
    health.os_store_gb = Math.round((all.store?.size_in_bytes || 0) / (1024 ** 3) * 100) / 100
    health.os_index_count = Object.keys(stats.indices || {}).length
  } catch {
    health.os_doc_count = 0
    health.os_store_gb = 0
  }

  // EPS (events per second) — count last 5 minutes vs 5 min before that
  try {
    const recent = await osQuery('POST', `/${getIndexPattern()}/_count`, {
      query: { range: { '@timestamp': { gte: 'now-5m', lte: 'now' } } },
    })
    const previous = await osQuery('POST', `/${getIndexPattern()}/_count`, {
      query: { range: { '@timestamp': { gte: 'now-10m', lte: 'now-5m' } } },
    })
    health.eps_current = Math.round((recent.count || 0) / 300 * 10) / 10
    health.eps_previous = Math.round((previous.count || 0) / 300 * 10) / 10
    health.logs_last_5m = recent.count || 0
  } catch {
    health.eps_current = 0
  }

  // OpenSearch disk usage
  try {
    const nodes = await osQuery('GET', '/_nodes/stats/fs')
    const nodeList = Object.values(nodes.nodes || {}) as any[]
    if (nodeList.length > 0) {
      const fs_data = nodeList[0].fs?.total || {}
      health.disk_total_gb = Math.round((fs_data.total_in_bytes || 0) / (1024 ** 3) * 10) / 10
      health.disk_free_gb = Math.round((fs_data.free_in_bytes || 0) / (1024 ** 3) * 10) / 10
      health.disk_used_gb = Math.round(((fs_data.total_in_bytes || 0) - (fs_data.free_in_bytes || 0)) / (1024 ** 3) * 10) / 10
      health.disk_percent = Math.round(((fs_data.total_in_bytes - fs_data.free_in_bytes) / fs_data.total_in_bytes) * 1000) / 10
    }
  } catch { /* ignore */ }

  // OpenSearch JVM memory
  try {
    const nodes = await osQuery('GET', '/_nodes/stats/jvm')
    const nodeList = Object.values(nodes.nodes || {}) as any[]
    if (nodeList.length > 0) {
      const jvm = nodeList[0].jvm?.mem || {}
      health.jvm_heap_used_mb = Math.round((jvm.heap_used_in_bytes || 0) / (1024 ** 2))
      health.jvm_heap_max_mb = Math.round((jvm.heap_max_in_bytes || 0) / (1024 ** 2))
      health.jvm_heap_percent = jvm.heap_used_percent || 0
    }
  } catch { /* ignore */ }

  // Container statuses from license checker state
  try {
    const stateFile = '/data/license_state.json'
    if (existsSync(stateFile)) {
      const state = JSON.parse(readFileSync(stateFile, 'utf8'))
      health.license_status = state.status
      health.license_last_check = state.last_check
      health.services_stopped = state.services_stopped
    }
  } catch { /* ignore */ }

  // AI tier
  try {
    const aiFile = process.env.AI_KEY_FILE || '/data/ai_key.json'
    if (existsSync(aiFile)) {
      const ai = JSON.parse(readFileSync(aiFile, 'utf8'))
      health.ai_tier = ai.ai_tier
      health.ai_daily_budget = ai.daily_budget
    }
  } catch { /* ignore */ }

  return NextResponse.json(health)
}
