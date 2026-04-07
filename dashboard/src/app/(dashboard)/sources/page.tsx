'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { useLanguage } from '@/components/LanguageProvider'
import { Server, Wifi, WifiOff } from 'lucide-react'

const SEVERITY_COLORS: Record<string, string> = {
  emergency: 'bg-red-600', alert: 'bg-orange-600', critical: 'bg-pink-600',
  error: 'bg-rose-500', warning: 'bg-amber-500 text-black', notice: 'bg-blue-500',
  info: 'bg-green-600', debug: 'bg-slate-500',
}

interface Source {
  name: string
  logCount: number
  lastSeen: string
  topSeverity: string
  applications: string[]
  active: boolean
}

export default function SourcesPage() {
  const { t } = useLanguage()
  const [sources, setSources] = useState<Source[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function fetch_() {
      try {
        const res = await fetch('/api/sources')
        if (res.ok) {
          const data = await res.json()
          setSources(data.sources)
        }
      } catch { /* ignore */ }
      setLoading(false)
    }
    fetch_()
    const interval = setInterval(fetch_, 60000)
    return () => clearInterval(interval)
  }, [])

  const activeCount = sources.filter(s => s.active).length
  const totalLogs = sources.reduce((sum, s) => sum + s.logCount, 0)

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold text-white">{t('sources.title')}</h1>

      {/* Summary cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="bg-slate-900 border-slate-800">
          <CardContent className="p-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-600/15"><Server size={20} className="text-blue-400" /></div>
              <div>
                <p className="text-sm text-slate-400">{t('sources.title')}</p>
                <p className="text-2xl font-bold text-white">{loading ? '...' : sources.length}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-slate-900 border-slate-800">
          <CardContent className="p-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-600/15"><Wifi size={20} className="text-green-400" /></div>
              <div>
                <p className="text-sm text-slate-400">{t('sources.active')}</p>
                <p className="text-2xl font-bold text-white">{loading ? '...' : activeCount}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-slate-900 border-slate-800">
          <CardContent className="p-6">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-600/15"><Server size={20} className="text-purple-400" /></div>
              <div>
                <p className="text-sm text-slate-400">{t('sources.logCount')}</p>
                <p className="text-2xl font-bold text-white">{loading ? '...' : totalLogs.toLocaleString()}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Sources table */}
      <Card className="bg-slate-900 border-slate-800">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-slate-300">{t('sources.title')}</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 text-xs">
                  <th className="text-start py-3 px-4 font-medium">{t('sources.status')}</th>
                  <th className="text-start py-3 px-4 font-medium">{t('sources.device')}</th>
                  <th className="text-start py-3 px-4 font-medium">{t('sources.logCount')}</th>
                  <th className="text-start py-3 px-4 font-medium">{t('sources.topSeverity')}</th>
                  <th className="text-start py-3 px-4 font-medium">{t('forensics.application')}</th>
                  <th className="text-start py-3 px-4 font-medium">{t('sources.lastSeen')}</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={6} className="py-8 text-center text-slate-500">{t('common.loading')}</td></tr>
                ) : sources.length === 0 ? (
                  <tr><td colSpan={6} className="py-8 text-center text-slate-500">{t('sources.noSources')}</td></tr>
                ) : sources.map((src) => (
                  <tr key={src.name} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                    <td className="py-3 px-4">
                      {src.active ? (
                        <div className="flex items-center gap-1.5">
                          <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                          <span className="text-xs text-green-400">{t('sources.active')}</span>
                        </div>
                      ) : (
                        <div className="flex items-center gap-1.5">
                          <WifiOff size={12} className="text-slate-500" />
                          <span className="text-xs text-slate-500">{t('sources.inactive')}</span>
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-4 text-white font-medium text-xs">{src.name}</td>
                    <td className="py-3 px-4 text-slate-300 text-xs">{src.logCount.toLocaleString()}</td>
                    <td className="py-3 px-4">
                      <Badge className={`${SEVERITY_COLORS[src.topSeverity] || 'bg-slate-600'} text-white text-[10px]`}>
                        {src.topSeverity}
                      </Badge>
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-xs">
                      {src.applications.join(', ')}
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-xs whitespace-nowrap">
                      {new Date(src.lastSeen).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
