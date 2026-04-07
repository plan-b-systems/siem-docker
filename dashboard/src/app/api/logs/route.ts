import { NextRequest, NextResponse } from 'next/server'
import { osQuery, getIndexPattern } from '@/lib/opensearch'

function sanitizeQuery(input: string): string {
  return input.replace(/[+\-=&|><!(){}[\]^"~*?:\\/]/g, '\\$&')
}

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url)
  const query = searchParams.get('q') || '*'
  const from = parseInt(searchParams.get('from') || '0', 10)
  const size = Math.min(100, parseInt(searchParams.get('size') || '50', 10))
  const rangeFrom = searchParams.get('range_from') || 'now-24h'
  const severity = searchParams.get('severity') || null
  const source = searchParams.get('source') || null

  const must: object[] = []
  const filter: object[] = [
    { range: { '@timestamp': { gte: rangeFrom, lte: 'now' } } },
  ]

  if (query && query !== '*') {
    must.push({ query_string: { query: sanitizeQuery(query), default_field: 'message', default_operator: 'AND' } })
  }
  if (severity) filter.push({ term: { severity } })
  if (source) filter.push({ term: { source } })

  const body = {
    track_total_hits: true,
    query: {
      bool: {
        ...(must.length > 0 ? { must } : { must: [{ match_all: {} }] }),
        filter,
      },
    },
    sort: [{ '@timestamp': { order: 'desc' } }],
    from,
    size,
    _source: ['@timestamp', 'source', 'source_ip', 'application', 'severity', 'severity_code', 'facility', 'message'],
  }

  try {
    const data = await osQuery('POST', `/${getIndexPattern()}/_search`, body)
    const logs = data.hits.hits.map((h: { _source: Record<string, unknown> }) => h._source)
    return NextResponse.json({ total: data.hits.total.value, logs })
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : 'Unknown error'
    if (msg.includes('index_not_found')) {
      return NextResponse.json({ total: 0, logs: [] })
    }
    console.error('Logs error:', msg)
    return NextResponse.json({ error: 'Search service unavailable' }, { status: 503 })
  }
}
