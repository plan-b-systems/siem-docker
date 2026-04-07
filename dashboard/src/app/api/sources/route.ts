import { NextResponse } from 'next/server'
import { osQuery, getIndexPattern } from '@/lib/opensearch'

export async function GET() {
  const query = {
    size: 0,
    aggs: {
      sources: {
        terms: { field: 'source', size: 100 },
        aggs: {
          last_seen: { max: { field: '@timestamp' } },
          top_severity: { min: { field: 'severity_code' } },
          top_severity_name: {
            terms: { field: 'severity', size: 1, order: { min_code: 'asc' } },
            aggs: { min_code: { min: { field: 'severity_code' } } },
          },
          applications: { terms: { field: 'application', size: 5 } },
        },
      },
    },
  }

  try {
    const data = await osQuery('POST', `/${getIndexPattern()}/_search`, query)

    const sources = (data.aggregations?.sources?.buckets || []).map(
      (b: {
        key: string
        doc_count: number
        last_seen: { value_as_string: string }
        top_severity_name: { buckets: { key: string }[] }
        applications: { buckets: { key: string; doc_count: number }[] }
      }) => {
        const lastSeen = new Date(b.last_seen.value_as_string)
        const minutesAgo = (Date.now() - lastSeen.getTime()) / 60000
        return {
          name: b.key,
          logCount: b.doc_count,
          lastSeen: b.last_seen.value_as_string,
          topSeverity: b.top_severity_name?.buckets?.[0]?.key || 'info',
          applications: (b.applications?.buckets || []).map(a => a.key),
          active: minutesAgo < 60, // active if seen in last hour
        }
      }
    )

    return NextResponse.json({ sources })
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : 'Unknown error'
    if (msg.includes('index_not_found')) {
      return NextResponse.json({ sources: [] })
    }
    console.error('Sources error:', msg)
    return NextResponse.json({ error: 'Sources service unavailable' }, { status: 503 })
  }
}
