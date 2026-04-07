'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useLanguage } from '@/components/LanguageProvider'
import {
  HardDrive, Cpu, Activity, Database, Server, Shield,
  CheckCircle, XCircle, AlertTriangle, Zap,
} from 'lucide-react'

function StatusDot({ ok }: { ok: boolean }) {
  return ok
    ? <div className="w-2.5 h-2.5 rounded-full bg-green-500 animate-pulse" />
    : <div className="w-2.5 h-2.5 rounded-full bg-red-500" />
}

function ProgressBar({ value, max, color = 'blue' }: { value: number; max: number; color?: string }) {
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0
  const barColor = pct > 90 ? 'bg-red-500' : pct > 75 ? 'bg-amber-500' : `bg-${color}-500`
  return (
    <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
      <div className={`h-full ${barColor} rounded-full transition-all`} style={{ width: `${pct}%` }} />
    </div>
  )
}

export default function HealthPage() {
  const { locale } = useLanguage()
  const [data, setData] = useState<Record<string, any> | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function load() {
      try {
        const res = await fetch('/api/system-health')
        if (res.ok) setData(await res.json())
      } catch { /* ignore */ }
      setLoading(false)
    }
    load()
    const interval = setInterval(load, 15000)
    return () => clearInterval(interval)
  }, [])

  const he = locale === 'he'

  if (loading) return <div className="p-6 text-slate-400">{he ? 'טוען...' : 'Loading...'}</div>
  if (!data) return <div className="p-6 text-red-400">{he ? 'שגיאה בטעינת נתוני מערכת' : 'Failed to load system health'}</div>

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold text-white">{he ? 'בריאות המערכת' : 'System Health'}</h1>

      {/* Top stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="bg-slate-900 border-slate-800">
          <CardContent className="p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-600/15">
                <Activity size={20} className="text-green-400" />
              </div>
              <div>
                <p className="text-xs text-slate-400">EPS</p>
                <p className="text-2xl font-bold text-white">{data.eps_current ?? 0}</p>
                <p className="text-[10px] text-slate-500">{he ? 'אירועים/שנייה' : 'events/sec'}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900 border-slate-800">
          <CardContent className="p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-600/15">
                <Database size={20} className="text-blue-400" />
              </div>
              <div>
                <p className="text-xs text-slate-400">{he ? 'לוגים' : 'Total Logs'}</p>
                <p className="text-2xl font-bold text-white">{(data.os_doc_count || 0).toLocaleString()}</p>
                <p className="text-[10px] text-slate-500">{data.os_index_count || 0} {he ? 'אינדקסים' : 'indices'}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900 border-slate-800">
          <CardContent className="p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-600/15">
                <HardDrive size={20} className="text-purple-400" />
              </div>
              <div>
                <p className="text-xs text-slate-400">{he ? 'אחסון לוגים' : 'Log Storage'}</p>
                <p className="text-2xl font-bold text-white">{data.os_store_gb ?? 0} GB</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-slate-900 border-slate-800">
          <CardContent className="p-5">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-cyan-600/15">
                <Shield size={20} className="text-cyan-400" />
              </div>
              <div>
                <p className="text-xs text-slate-400">{he ? 'רישיון' : 'License'}</p>
                <p className="text-lg font-bold text-white">{data.license_status || 'UNKNOWN'}</p>
                <p className="text-[10px] text-slate-500">AI: {data.ai_tier || 'NONE'}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Disk */}
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-slate-300 flex items-center gap-2">
              <HardDrive size={16} /> {he ? 'דיסק' : 'Disk Usage'}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex justify-between text-sm">
              <span className="text-slate-400">{he ? 'תפוס' : 'Used'}: {data.disk_used_gb ?? '?'} GB</span>
              <span className="text-slate-400">{he ? 'סה"כ' : 'Total'}: {data.disk_total_gb ?? '?'} GB</span>
            </div>
            <ProgressBar value={data.disk_used_gb || 0} max={data.disk_total_gb || 1} />
            <div className="flex justify-between text-xs">
              <span className="text-slate-500">{he ? 'פנוי' : 'Free'}: {data.disk_free_gb ?? '?'} GB</span>
              <span className={`font-medium ${(data.disk_percent || 0) > 85 ? 'text-red-400' : 'text-green-400'}`}>
                {data.disk_percent ?? 0}%
              </span>
            </div>
          </CardContent>
        </Card>

        {/* JVM Memory */}
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-slate-300 flex items-center gap-2">
              <Cpu size={16} /> {he ? 'זיכרון OpenSearch' : 'OpenSearch Memory'}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex justify-between text-sm">
              <span className="text-slate-400">{he ? 'בשימוש' : 'Heap Used'}: {data.jvm_heap_used_mb ?? '?'} MB</span>
              <span className="text-slate-400">Max: {data.jvm_heap_max_mb ?? '?'} MB</span>
            </div>
            <ProgressBar value={data.jvm_heap_used_mb || 0} max={data.jvm_heap_max_mb || 1} color="purple" />
            <span className={`text-xs font-medium ${(data.jvm_heap_percent || 0) > 85 ? 'text-red-400' : 'text-green-400'}`}>
              {data.jvm_heap_percent ?? 0}%
            </span>
          </CardContent>
        </Card>

        {/* OpenSearch Cluster */}
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-slate-300 flex items-center gap-2">
              <Database size={16} /> OpenSearch Cluster
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div className="flex items-center gap-2">
                <StatusDot ok={data.os_cluster === 'green' || data.os_cluster === 'yellow'} />
                <span className="text-slate-400">{he ? 'סטטוס' : 'Status'}:</span>
                <span className={`font-medium ${data.os_cluster === 'green' ? 'text-green-400' : data.os_cluster === 'yellow' ? 'text-amber-400' : 'text-red-400'}`}>
                  {data.os_cluster}
                </span>
              </div>
              <div>
                <span className="text-slate-400">Shards: </span>
                <span className="text-white">{data.os_shards_active ?? '?'} active</span>
              </div>
              <div>
                <span className="text-slate-400">{he ? 'מסמכים' : 'Documents'}: </span>
                <span className="text-white">{(data.os_doc_count || 0).toLocaleString()}</span>
              </div>
              <div>
                <span className="text-slate-400">{he ? 'אינדקסים' : 'Indices'}: </span>
                <span className="text-white">{data.os_index_count || 0}</span>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Ingestion */}
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-slate-300 flex items-center gap-2">
              <Zap size={16} /> {he ? 'קליטת לוגים' : 'Log Ingestion'}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-slate-400">EPS ({he ? 'נוכחי' : 'current'}): </span>
                <span className="text-white font-medium">{data.eps_current ?? 0}</span>
              </div>
              <div>
                <span className="text-slate-400">EPS ({he ? 'קודם' : 'previous'}): </span>
                <span className="text-white">{data.eps_previous ?? 0}</span>
              </div>
              <div>
                <span className="text-slate-400">{he ? 'לוגים ב-5 דקות' : 'Last 5 min'}: </span>
                <span className="text-white">{(data.logs_last_5m || 0).toLocaleString()}</span>
              </div>
              <div>
                <span className="text-slate-400">{he ? 'אחסון כולל' : 'Total storage'}: </span>
                <span className="text-white">{data.os_store_gb ?? 0} GB</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
