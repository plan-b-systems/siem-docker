'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { useLanguage } from '@/components/LanguageProvider'
import { Search, Download, RefreshCw, ChevronDown, ChevronUp, ChevronLeft, ChevronRight } from 'lucide-react'

const SEVERITY_COLORS: Record<string, string> = {
  emergency: 'bg-red-600', alert: 'bg-orange-600', critical: 'bg-pink-600',
  error: 'bg-rose-500', warning: 'bg-amber-500 text-black', notice: 'bg-blue-500',
  info: 'bg-green-600', debug: 'bg-slate-500',
}

const SEVERITIES = ['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug']

const TIME_RANGES = [
  { key: 'now-15m', label: 'time.15m' as const },
  { key: 'now-1h', label: 'time.1h' as const },
  { key: 'now-6h', label: 'time.6h' as const },
  { key: 'now-24h', label: 'time.24h' as const },
  { key: 'now-7d', label: 'time.7d' as const },
  { key: 'now-30d', label: 'time.30d' as const },
]

interface LogEntry {
  '@timestamp': string
  source: string
  source_ip: string
  application: string
  severity: string
  severity_code: number
  facility: string
  message: string
}

const PAGE_SIZE = 50

export default function ForensicsPage() {
  const { t } = useLanguage()
  const [query, setQuery] = useState('')
  const [range, setRange] = useState('now-24h')
  const [severity, setSeverity] = useState('')
  const [page, setPage] = useState(0)
  const [total, setTotal] = useState(0)
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [expandedRow, setExpandedRow] = useState<number | null>(null)
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const fetchLogs = useCallback(async () => {
    const params = new URLSearchParams({
      range_from: range,
      from: String(page * PAGE_SIZE),
      size: String(PAGE_SIZE),
    })
    if (query) params.set('q', query)
    if (severity) params.set('severity', severity)

    try {
      const res = await fetch(`/api/logs?${params}`)
      if (res.ok) {
        const data = await res.json()
        setLogs(data.logs)
        setTotal(data.total)
      }
    } catch { /* ignore */ }
    setLoading(false)
  }, [range, page, query, severity])

  useEffect(() => {
    setLoading(true)
    fetchLogs()
  }, [fetchLogs])

  useEffect(() => {
    if (autoRefresh) {
      intervalRef.current = setInterval(fetchLogs, 10000)
    } else if (intervalRef.current) {
      clearInterval(intervalRef.current)
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current) }
  }, [autoRefresh, fetchLogs])

  function handleSearch(e: React.FormEvent) {
    e.preventDefault()
    setPage(0)
    fetchLogs()
  }

  function exportCSV() {
    const header = 'Timestamp,Source,Source IP,Application,Severity,Facility,Message'
    const rows = logs.map(l =>
      `"${l['@timestamp']}","${l.source}","${l.source_ip}","${l.application}","${l.severity}","${l.facility}","${(l.message || '').replace(/"/g, '""')}"`
    )
    const csv = [header, ...rows].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `siem-logs-${new Date().toISOString().split('T')[0]}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  const totalPages = Math.ceil(total / PAGE_SIZE)

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">{t('forensics.title')}</h1>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              autoRefresh ? 'bg-green-600/20 text-green-400' : 'bg-slate-800 text-slate-400 hover:text-white'
            }`}
          >
            <RefreshCw size={14} className={autoRefresh ? 'animate-spin' : ''} />
            {t('forensics.refresh')}
          </button>
          <button
            onClick={exportCSV}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 text-slate-400 hover:text-white transition-colors"
          >
            <Download size={14} />
            {t('forensics.export')}
          </button>
        </div>
      </div>

      {/* Filters */}
      <Card className="bg-slate-900 border-slate-800">
        <CardContent className="p-4">
          <form onSubmit={handleSearch} className="flex flex-wrap gap-3 items-center">
            <div className="flex-1 min-w-[200px] relative">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={t('forensics.search')}
                className="w-full h-9 pl-9 pr-3 rounded-lg bg-slate-800 border border-slate-700 text-white text-sm placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>
            <select
              value={severity}
              onChange={(e) => { setSeverity(e.target.value); setPage(0) }}
              className="h-9 px-3 rounded-lg bg-slate-800 border border-slate-700 text-white text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              <option value="">{t('forensics.allSeverities')}</option>
              {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <div className="flex gap-1 bg-slate-800 rounded-lg p-0.5">
              {TIME_RANGES.map(({ key, label }) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => { setRange(key); setPage(0) }}
                  className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors ${
                    range === key ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {t(label)}
                </button>
              ))}
            </div>
          </form>
        </CardContent>
      </Card>

      {/* Results */}
      <Card className="bg-slate-900 border-slate-800">
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 text-xs">
                  <th className="text-start py-3 px-4 font-medium w-8"></th>
                  <th className="text-start py-3 px-4 font-medium">{t('forensics.timestamp')}</th>
                  <th className="text-start py-3 px-4 font-medium">{t('forensics.severity')}</th>
                  <th className="text-start py-3 px-4 font-medium">{t('forensics.source')}</th>
                  <th className="text-start py-3 px-4 font-medium">{t('forensics.application')}</th>
                  <th className="text-start py-3 px-4 font-medium">{t('forensics.message')}</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={6} className="py-8 text-center text-slate-500">{t('common.loading')}</td></tr>
                ) : logs.length === 0 ? (
                  <tr><td colSpan={6} className="py-8 text-center text-slate-500">{t('forensics.noLogs')}</td></tr>
                ) : logs.map((log, i) => (
                  <>
                    <tr
                      key={i}
                      onClick={() => setExpandedRow(expandedRow === i ? null : i)}
                      className="border-b border-slate-800/50 hover:bg-slate-800/30 cursor-pointer"
                    >
                      <td className="py-2 px-4 text-slate-500">
                        {expandedRow === i ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                      </td>
                      <td className="py-2 px-4 text-slate-300 whitespace-nowrap text-xs">
                        {new Date(log['@timestamp']).toLocaleString()}
                      </td>
                      <td className="py-2 px-4">
                        <Badge className={`${SEVERITY_COLORS[log.severity] || 'bg-slate-600'} text-white text-[10px]`}>
                          {log.severity}
                        </Badge>
                      </td>
                      <td className="py-2 px-4 text-slate-300 text-xs">{log.source}</td>
                      <td className="py-2 px-4 text-slate-400 text-xs">{log.application}</td>
                      <td className="py-2 px-4 text-slate-300 text-xs max-w-lg truncate">{log.message}</td>
                    </tr>
                    {expandedRow === i && (
                      <tr key={`${i}-exp`} className="bg-slate-800/20">
                        <td colSpan={6} className="px-8 py-4">
                          <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-xs">
                            <div><span className="text-slate-500">Source IP:</span> <span className="text-white">{log.source_ip}</span></div>
                            <div><span className="text-slate-500">Facility:</span> <span className="text-white">{log.facility}</span></div>
                            <div><span className="text-slate-500">Severity Code:</span> <span className="text-white">{log.severity_code}</span></div>
                            <div><span className="text-slate-500">Application:</span> <span className="text-white">{log.application}</span></div>
                          </div>
                          <div className="mt-3 p-3 bg-slate-950 rounded-lg text-xs text-slate-200 font-mono whitespace-pre-wrap break-all">
                            {log.message}
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {total > 0 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-slate-800">
              <span className="text-xs text-slate-400">
                {t('forensics.showing')} {page * PAGE_SIZE + 1}-{Math.min((page + 1) * PAGE_SIZE, total)} {t('forensics.of')} {total.toLocaleString()} {t('common.logs')}
              </span>
              <div className="flex gap-1">
                <button
                  onClick={() => setPage(Math.max(0, page - 1))}
                  disabled={page === 0}
                  className="flex items-center gap-1 px-3 py-1.5 text-xs rounded-lg bg-slate-800 text-slate-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed"
                >
                  <ChevronLeft size={14} /> {t('forensics.prev')}
                </button>
                <button
                  onClick={() => setPage(page + 1)}
                  disabled={page >= totalPages - 1}
                  className="flex items-center gap-1 px-3 py-1.5 text-xs rounded-lg bg-slate-800 text-slate-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed"
                >
                  {t('forensics.next')} <ChevronRight size={14} />
                </button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
