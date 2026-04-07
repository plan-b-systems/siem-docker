'use client'

import { useState, useEffect, useCallback } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { useLanguage } from '@/components/LanguageProvider'
import { ShieldAlert, AlertTriangle, Flame, XCircle } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'

const SEVERITY_CONFIG: Record<string, { color: string; bg: string; icon: typeof ShieldAlert }> = {
  emergency: { color: 'text-red-500', bg: 'bg-red-500/10', icon: Flame },
  alert: { color: 'text-orange-500', bg: 'bg-orange-500/10', icon: AlertTriangle },
  critical: { color: 'text-pink-500', bg: 'bg-pink-500/10', icon: ShieldAlert },
  error: { color: 'text-rose-400', bg: 'bg-rose-500/10', icon: XCircle },
}

const SEVERITY_BADGE: Record<string, string> = {
  emergency: 'bg-red-600 text-white',
  alert: 'bg-orange-600 text-white',
  critical: 'bg-pink-600 text-white',
  error: 'bg-rose-500 text-white',
}

const TIME_RANGES = [
  { key: 'now-1h', label: 'time.1h' as const },
  { key: 'now-6h', label: 'time.6h' as const },
  { key: 'now-24h', label: 'time.24h' as const },
  { key: 'now-7d', label: 'time.7d' as const },
  { key: 'now-30d', label: 'time.30d' as const },
]

interface Threat {
  '@timestamp': string
  source: string
  application: string
  severity: string
  message: string
}

interface ThreatsData {
  total: number
  threats: Threat[]
  bySeverity: { name: string; count: number }[]
  bySource: { name: string; count: number }[]
  timeline: Record<string, unknown>[]
}

export default function ThreatsPage() {
  const { t } = useLanguage()
  const [range, setRange] = useState('now-24h')
  const [data, setData] = useState<ThreatsData | null>(null)
  const [loading, setLoading] = useState(true)

  const fetchThreats = useCallback(async () => {
    try {
      const res = await fetch(`/api/threats?range_from=${range}`)
      if (res.ok) setData(await res.json())
    } catch { /* ignore */ }
    setLoading(false)
  }, [range])

  useEffect(() => {
    setLoading(true)
    fetchThreats()
    const interval = setInterval(fetchThreats, 30000)
    return () => clearInterval(interval)
  }, [fetchThreats])

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">{t('threats.title')}</h1>
        <div className="flex gap-1 bg-slate-900 rounded-lg p-1">
          {TIME_RANGES.map(({ key, label }) => (
            <button
              key={key}
              onClick={() => setRange(key)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                range === key ? 'bg-blue-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              {t(label)}
            </button>
          ))}
        </div>
      </div>

      {/* Severity summary cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {(['emergency', 'alert', 'critical', 'error'] as const).map((sev) => {
          const cfg = SEVERITY_CONFIG[sev]
          const Icon = cfg.icon
          const count = data?.bySeverity.find(s => s.name === sev)?.count || 0
          return (
            <Card key={sev} className="bg-slate-900 border-slate-800">
              <CardContent className="p-5">
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-lg ${cfg.bg}`}>
                    <Icon size={20} className={cfg.color} />
                  </div>
                  <div>
                    <p className="text-xs text-slate-400 capitalize">{sev}</p>
                    <p className="text-xl font-bold text-white">{loading ? '...' : count}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Attack sources */}
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-slate-300">{t('threats.attackSources')}</CardTitle>
          </CardHeader>
          <CardContent>
            {data?.bySource.length ? (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={data.bySource} layout="vertical" margin={{ left: 0, right: 10 }}>
                  <XAxis type="number" hide />
                  <YAxis type="category" dataKey="name" width={120} tick={{ fontSize: 11, fill: '#94a3b8' }} />
                  <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }} />
                  <Bar dataKey="count" fill="#ef4444" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <p className="text-slate-500 text-sm py-8 text-center">{t('threats.noThreats')}</p>
            )}
          </CardContent>
        </Card>

        {/* Threat timeline */}
        <Card className="bg-slate-900 border-slate-800 lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-slate-300">{t('threats.timeline')}</CardTitle>
          </CardHeader>
          <CardContent>
            {data?.timeline.length ? (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={data.timeline} margin={{ top: 5, right: 10, left: 0, bottom: 0 }}>
                  <XAxis
                    dataKey="time"
                    tick={{ fontSize: 10, fill: '#64748b' }}
                    tickFormatter={(v) => {
                      const d = new Date(v)
                      return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`
                    }}
                  />
                  <YAxis tick={{ fontSize: 10, fill: '#64748b' }} />
                  <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }} />
                  <Bar dataKey="emergency" stackId="a" fill="#dc2626" />
                  <Bar dataKey="alert" stackId="a" fill="#ea580c" />
                  <Bar dataKey="critical" stackId="a" fill="#e11d48" />
                  <Bar dataKey="error" stackId="a" fill="#f43f5e" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <p className="text-slate-500 text-sm py-8 text-center">{t('threats.noThreats')}</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Threat events table */}
      <Card className="bg-slate-900 border-slate-800">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-slate-300">
            {t('threats.title')} ({loading ? '...' : data?.total || 0})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="text-start py-2 px-3 font-medium">{t('forensics.timestamp')}</th>
                  <th className="text-start py-2 px-3 font-medium">{t('forensics.severity')}</th>
                  <th className="text-start py-2 px-3 font-medium">{t('forensics.source')}</th>
                  <th className="text-start py-2 px-3 font-medium">{t('forensics.application')}</th>
                  <th className="text-start py-2 px-3 font-medium">{t('forensics.message')}</th>
                </tr>
              </thead>
              <tbody>
                {data?.threats.length ? data.threats.map((threat, i) => (
                  <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                    <td className="py-2 px-3 text-slate-300 whitespace-nowrap text-xs">
                      {new Date(threat['@timestamp']).toLocaleString()}
                    </td>
                    <td className="py-2 px-3">
                      <Badge className={SEVERITY_BADGE[threat.severity] || 'bg-slate-600 text-white'}>
                        {threat.severity}
                      </Badge>
                    </td>
                    <td className="py-2 px-3 text-slate-300 text-xs">{threat.source}</td>
                    <td className="py-2 px-3 text-slate-400 text-xs">{threat.application}</td>
                    <td className="py-2 px-3 text-slate-300 text-xs max-w-md truncate">{threat.message}</td>
                  </tr>
                )) : (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-500">{t('threats.noThreats')}</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
