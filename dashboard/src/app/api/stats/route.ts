import { NextRequest, NextResponse } from 'next/server'
import { osQuery, getIndexPattern } from '@/lib/opensearch'

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url)
  const rangeFrom = searchParams.get('range_from') || 'now-24h'
  const rangeTo = searchParams.get('range_to') || 'now'
  const source = searchParams.get('source') || null

  const filter: object[] = [
    { range: { '@timestamp': { gte: rangeFrom, lte: rangeTo } } },
  ]
  if (source) {
    filter.push({ term: { source } })
  }

  const query = {
    size: 0,
    track_total_hits: true,
    query: { bool: { filter } },
    aggs: {
      severity_counts: {
        terms: { field: 'severity', size: 10 },
      },
      top_sources: {
        terms: { field: 'source', size: 10 },
      },
      top_applications: {
        terms: { field: 'application', size: 10 },
      },
      logs_over_time: {
        date_histogram: {
          field: '@timestamp',
          fixed_interval: rangeFrom === 'now-15m' ? '1m'
            : rangeFrom === 'now-1h' ? '5m'
            : rangeFrom === 'now-6h' ? '30m'
            : rangeFrom === 'now-24h' ? '1h'
            : rangeFrom === 'now-7d' ? '6h'
            : '1d',
        },
      },
    },
  }

  try {
    const data = await osQuery('POST', `/${getIndexPattern()}/_search`, query)

    const total = data.hits.total.value
    const severity = (data.aggregations?.severity_counts?.buckets || []).map(
      (b: { key: string; doc_count: number }) => ({ name: b.key, count: b.doc_count })
    )
    const sources = (data.aggregations?.top_sources?.buckets || []).map(
      (b: { key: string; doc_count: number }) => ({ name: b.key, count: b.doc_count })
    )
    const applications = (data.aggregations?.top_applications?.buckets || []).map(
      (b: { key: string; doc_count: number }) => ({ name: b.key, count: b.doc_count })
    )
    const timeline = (data.aggregations?.logs_over_time?.buckets || []).map(
      (b: { key_as_string: string; doc_count: number }) => ({
        time: b.key_as_string,
        count: b.doc_count,
      })
    )

    return NextResponse.json({ total, severity, sources, applications, timeline })
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : 'Unknown error'
    if (msg.includes('index_not_found')) {
      return NextResponse.json({ total: 0, severity: [], sources: [], applications: [], timeline: [] })
    }
    console.error('Stats error:', msg)
    return NextResponse.json({ error: 'Stats service unavailable' }, { status: 503 })
  }
}
