import { NextRequest, NextResponse } from 'next/server'
import { osQuery, getIndexPattern } from '@/lib/opensearch'

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url)
  const rangeFrom = searchParams.get('range_from') || 'now-24h'
  const page = parseInt(searchParams.get('page') || '0', 10)
  const size = 50

  const query = {
    size,
    from: page * size,
    track_total_hits: true,
    sort: [{ '@timestamp': 'desc' }],
    query: {
      bool: {
        filter: [
          { range: { '@timestamp': { gte: rangeFrom, lte: 'now' } } },
          { terms: { severity: ['emergency', 'alert', 'critical', 'error'] } },
        ],
      },
    },
    aggs: {
      by_severity: {
        terms: { field: 'severity', size: 10 },
      },
      by_source: {
        terms: { field: 'source', size: 10 },
      },
      timeline: {
        date_histogram: {
          field: '@timestamp',
          fixed_interval: rangeFrom === 'now-1h' ? '5m'
            : rangeFrom === 'now-6h' ? '30m'
            : rangeFrom === 'now-24h' ? '1h'
            : rangeFrom === 'now-7d' ? '6h'
            : '1d',
        },
        aggs: {
          by_severity: {
            terms: { field: 'severity', size: 4 },
          },
        },
      },
    },
  }

  try {
    const data = await osQuery('POST', `/${getIndexPattern()}/_search`, query)

    const total = data.hits.total.value
    const threats = data.hits.hits.map((h: { _source: Record<string, unknown> }) => h._source)

    const bySeverity = (data.aggregations?.by_severity?.buckets || []).map(
      (b: { key: string; doc_count: number }) => ({ name: b.key, count: b.doc_count })
    )
    const bySource = (data.aggregations?.by_source?.buckets || []).map(
      (b: { key: string; doc_count: number }) => ({ name: b.key, count: b.doc_count })
    )
    const timeline = (data.aggregations?.timeline?.buckets || []).map(
      (b: { key_as_string: string; doc_count: number; by_severity: { buckets: { key: string; doc_count: number }[] } }) => ({
        time: b.key_as_string,
        total: b.doc_count,
        ...Object.fromEntries((b.by_severity?.buckets || []).map(s => [s.key, s.doc_count])),
      })
    )

    return NextResponse.json({ total, threats, bySeverity, bySource, timeline })
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : 'Unknown error'
    if (msg.includes('index_not_found')) {
      return NextResponse.json({ total: 0, threats: [], bySeverity: [], bySource: [], timeline: [] })
    }
    console.error('Threats error:', msg)
    return NextResponse.json({ error: 'Threats service unavailable' }, { status: 503 })
  }
}
