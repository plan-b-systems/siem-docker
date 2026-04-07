'use client'

import { useState, useEffect, useCallback } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useLanguage } from '@/components/LanguageProvider'
import { Activity, ShieldAlert, Server, AppWindow } from 'lucide-react'
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  AreaChart, Area, ResponsiveContainer,
} from 'recharts'

const SEVERITY_COLORS: Record<string, string> = {
  emergency: '#dc2626', alert: '#ea580c', critical: '#e11d48',
  error: '#f43f5e', warning: '#f59e0b', notice: '#3b82f6',
  info: '#22c55e', debug: '#6b7280',
}

const TIME_RANGES = [
  { key: 'now-15m', label: 'time.15m' as const },
  { key: 'now-1h', label: 'time.1h' as const },
  { key: 'now-6h', label: 'time.6h' as const },
  { key: 'now-24h', label: 'time.24h' as const },
  { key: 'now-7d', label: 'time.7d' as const },
  { key: 'now-30d', label: 'time.30d' as const },
]

interface Stats {
  total: number
  severity: { name: string; count: number }[]
  sources: { name: string; count: number }[]
  applications: { name: string; count: number }[]
  timeline: { time: string; count: number }[]
}

export default function OverviewPage() {
  const { t } = useLanguage()
  const [range, setRange] = useState('now-24h')
  const [stats, setStats] = useState<Stats | null>(null)
  const [loading, setLoading] = useState(true)

  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch(`/api/stats?range_from=${range}`)
      if (res.ok) setStats(await res.json())
    } catch { /* ignore */ }
    setLoading(false)
  }, [range])

  useEffect(() => {
    setLoading(true)
    fetchStats()
    const interval = setInterval(fetchStats, 30000)
    return () => clearInterval(interval)
  }, [fetchStats])

  const threatCount = stats?.severity
    .filter(s => ['emergency', 'alert', 'critical', 'error'].includes(s.name))
    .reduce((sum, s) => sum + s.count, 0) || 0

  return (
    <div className="p-6 space-y-6">
      {/* Header + time range */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">{t('overview.title')}</h1>
        <div className="flex gap-1 bg-slate-900 rounded-lg p-1">
          {TIME_RANGES.map(({ key, label }) => (
            <button
              key={key}
              onClick={() => setRange(key)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                range === key
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {t(label)}
            </button>
          ))}
        </div>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-slate-900 border-slate-800">
          <CardContent className="p-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-600/15">
                <Activity size={20} className="text-blue-400" />
              </div>
              <div>
                <p className="text-sm text-slate-400">{t('overview.totalLogs')}</p>
                <p className="text-2xl font-bold text-white">
                  {loading ? '...' : (stats?.total || 0).toLocaleString()}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900 border-slate-800">
          <CardContent className="p-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-red-600/15">
                <ShieldAlert size={20} className="text-red-400" />
              </div>
              <div>
                <p className="text-sm text-slate-400">{t('nav.threats')}</p>
                <p className="text-2xl font-bold text-white">
                  {loading ? '...' : threatCount.toLocaleString()}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900 border-slate-800">
          <CardContent className="p-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-600/15">
                <Server size={20} className="text-green-400" />
              </div>
              <div>
                <p className="text-sm text-slate-400">{t('overview.topSources')}</p>
                <p className="text-2xl font-bold text-white">
                  {loading ? '...' : stats?.sources.length || 0}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900 border-slate-800">
          <CardContent className="p-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-600/15">
                <AppWindow size={20} className="text-purple-400" />
              </div>
              <div>
                <p className="text-sm text-slate-400">{t('overview.topApps')}</p>
                <p className="text-2xl font-bold text-white">
                  {loading ? '...' : stats?.applications.length || 0}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Severity pie */}
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-slate-300">{t('overview.severity')}</CardTitle>
          </CardHeader>
          <CardContent>
            {stats?.severity.length ? (
              <div className="flex items-center gap-4">
                <ResponsiveContainer width={140} height={140}>
                  <PieChart>
                    <Pie data={stats.severity} dataKey="count" nameKey="name" cx="50%" cy="50%" innerRadius={35} outerRadius={65} paddingAngle={2}>
                      {stats.severity.map((s) => (
                        <Cell key={s.name} fill={SEVERITY_COLORS[s.name] || '#6b7280'} />
                      ))}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
                <div className="space-y-1.5 text-xs">
                  {stats.severity.map((s) => (
                    <div key={s.name} className="flex items-center gap-2">
                      <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: SEVERITY_COLORS[s.name] || '#6b7280' }} />
                      <span className="text-slate-400 capitalize">{s.name}</span>
                      <span className="text-white font-medium ml-auto">{s.count}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-slate-500 text-sm py-8 text-center">{t('common.noData')}</p>
            )}
          </CardContent>
        </Card>

        {/* Top sources bar */}
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-slate-300">{t('overview.topSources')}</CardTitle>
          </CardHeader>
          <CardContent>
            {stats?.sources.length ? (
              <ResponsiveContainer width="100%" height={160}>
                <BarChart data={stats.sources} layout="vertical" margin={{ left: 0, right: 10 }}>
                  <XAxis type="number" hide />
                  <YAxis type="category" dataKey="name" width={100} tick={{ fontSize: 11, fill: '#94a3b8' }} />
                  <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }} />
                  <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <p className="text-slate-500 text-sm py-8 text-center">{t('common.noData')}</p>
            )}
          </CardContent>
        </Card>

        {/* Top applications bar */}
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-slate-300">{t('overview.topApps')}</CardTitle>
          </CardHeader>
          <CardContent>
            {stats?.applications.length ? (
              <ResponsiveContainer width="100%" height={160}>
                <BarChart data={stats.applications} layout="vertical" margin={{ left: 0, right: 10 }}>
                  <XAxis type="number" hide />
                  <YAxis type="category" dataKey="name" width={100} tick={{ fontSize: 11, fill: '#94a3b8' }} />
                  <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }} />
                  <Bar dataKey="count" fill="#8b5cf6" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <p className="text-slate-500 text-sm py-8 text-center">{t('common.noData')}</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Timeline */}
      <Card className="bg-slate-900 border-slate-800">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-slate-300">{t('overview.logsOverTime')}</CardTitle>
        </CardHeader>
        <CardContent>
          {stats?.timeline.length ? (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={stats.timeline} margin={{ top: 5, right: 10, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorLogs" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="time"
                  tick={{ fontSize: 10, fill: '#64748b' }}
                  tickFormatter={(v) => {
                    const d = new Date(v)
                    return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`
                  }}
                />
                <YAxis tick={{ fontSize: 10, fill: '#64748b' }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }}
                  labelFormatter={(v) => new Date(v).toLocaleString()}
                />
                <Area type="monotone" dataKey="count" stroke="#3b82f6" fillOpacity={1} fill="url(#colorLogs)" />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-slate-500 text-sm py-8 text-center">{t('common.noData')}</p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
