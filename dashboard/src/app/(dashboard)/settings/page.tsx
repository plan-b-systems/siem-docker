'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useLanguage } from '@/components/LanguageProvider'
import { Settings, Globe, Clock, Database, Shield, CheckCircle, XCircle, Cpu, Zap } from 'lucide-react'

export default function SettingsPage() {
  const { t, locale, setLocale } = useLanguage()
  const [settings, setSettings] = useState<Record<string, string | number>>({})
  const [license, setLicense] = useState<Record<string, unknown> | null>(null)
  const [osStatus, setOsStatus] = useState<'checking' | 'connected' | 'disconnected'>('checking')
  const [saved, setSaved] = useState(false)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/license').then(r => r.ok ? r.json() : null).then(d => setLicense(d)).catch(() => {})
  }, [])

  useEffect(() => {
    async function load() {
      try {
        const res = await fetch('/api/settings')
        if (res.ok) {
          const data = await res.json()
          setSettings(data)
          if (data.opensearch_status === 'disconnected') {
            setOsStatus('disconnected')
          } else {
            setOsStatus('connected')
          }
        }
      } catch {
        setOsStatus('disconnected')
      }
      setLoading(false)
    }
    load()
  }, [])

  async function handleSave() {
    const payload = {
      ...settings,
      language: locale,
    }
    try {
      const res = await fetch('/api/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      if (res.ok) {
        setSaved(true)
        setTimeout(() => setSaved(false), 3000)
      }
    } catch { /* ignore */ }
  }

  if (loading) {
    return <div className="p-6 text-slate-400">{t('common.loading')}</div>
  }

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold text-white">{t('settings.title')}</h1>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Language */}
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-slate-300 flex items-center gap-2">
              <Globe size={16} /> {t('settings.language')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex gap-3">
              <button
                onClick={() => setLocale('he')}
                className={`flex-1 py-3 rounded-lg text-sm font-medium transition-colors ${
                  locale === 'he' ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                {t('settings.hebrew')} 🇮🇱
              </button>
              <button
                onClick={() => setLocale('en')}
                className={`flex-1 py-3 rounded-lg text-sm font-medium transition-colors ${
                  locale === 'en' ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                {t('settings.english')} 🇬🇧
              </button>
            </div>
          </CardContent>
        </Card>

        {/* Timezone */}
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-slate-300 flex items-center gap-2">
              <Clock size={16} /> {t('settings.timezone')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <select
              value={settings.timezone as string || 'Asia/Jerusalem'}
              onChange={(e) => setSettings({ ...settings, timezone: e.target.value })}
              className="w-full h-10 px-3 rounded-lg bg-slate-800 border border-slate-700 text-white text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              <option value="Asia/Jerusalem">Asia/Jerusalem (IST)</option>
              <option value="Europe/London">Europe/London (GMT)</option>
              <option value="America/New_York">America/New_York (EST)</option>
              <option value="America/Los_Angeles">America/Los_Angeles (PST)</option>
              <option value="Europe/Berlin">Europe/Berlin (CET)</option>
              <option value="Asia/Tokyo">Asia/Tokyo (JST)</option>
            </select>
          </CardContent>
        </Card>

        {/* Retention */}
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-slate-300 flex items-center gap-2">
              <Database size={16} /> {t('settings.retention')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <input
              type="number"
              min={30}
              max={3650}
              value={settings.retention_days as number || 730}
              onChange={(e) => setSettings({ ...settings, retention_days: parseInt(e.target.value) })}
              className="w-full h-10 px-3 rounded-lg bg-slate-800 border border-slate-700 text-white text-sm focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
            <p className="text-xs text-slate-500 mt-2">
              {locale === 'he' ? 'מינימום 730 ימים לפי תקנות הגנת הפרטיות' : 'Minimum 730 days per Israeli privacy regulation'}
            </p>
          </CardContent>
        </Card>

        {/* Client info */}
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-slate-300 flex items-center gap-2">
              <Shield size={16} /> {t('settings.clientInfo')}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <label className="text-xs text-slate-500">{t('settings.clientName')}</label>
              <div className="h-10 px-3 rounded-lg bg-slate-800/50 border border-slate-700/50 text-slate-300 text-sm flex items-center">
                {settings.client_name || '-'}
              </div>
            </div>
            <div>
              <label className="text-xs text-slate-500">{t('settings.clientId')}</label>
              <div className="h-10 px-3 rounded-lg bg-slate-800/50 border border-slate-700/50 text-slate-300 text-sm flex items-center font-mono">
                {settings.client_id || '-'}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* OpenSearch status */}
        <Card className="bg-slate-900 border-slate-800">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-slate-300 flex items-center gap-2">
              <Database size={16} /> {t('settings.opensearch')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-3">
              {osStatus === 'connected' ? (
                <>
                  <CheckCircle size={20} className="text-green-500" />
                  <span className="text-green-400 text-sm">{t('settings.connected')}</span>
                </>
              ) : osStatus === 'disconnected' ? (
                <>
                  <XCircle size={20} className="text-red-500" />
                  <span className="text-red-400 text-sm">{t('settings.disconnected')}</span>
                </>
              ) : (
                <span className="text-slate-400 text-sm">{t('common.loading')}</span>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* License Status */}
      {license && (
        <Card className="bg-slate-900 border-slate-800 lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium text-slate-300 flex items-center gap-2">
              <Zap size={16} /> {locale === 'he' ? 'סטטוס רישיון' : 'License Status'}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div>
                <span className="text-slate-500">{locale === 'he' ? 'סטטוס' : 'Status'}</span>
                <div className="mt-1 flex items-center gap-2">
                  {license.active ? (
                    <><CheckCircle size={16} className="text-green-500" /><span className="text-green-400">{license.status as string}</span></>
                  ) : (
                    <><XCircle size={16} className="text-red-500" /><span className="text-red-400">{license.status as string}</span></>
                  )}
                </div>
              </div>
              <div>
                <span className="text-slate-500">{locale === 'he' ? 'בדיקה אחרונה' : 'Last Check'}</span>
                <div className="mt-1 text-white text-xs">
                  {license.last_check ? new Date(license.last_check as string).toLocaleString() : '—'}
                </div>
              </div>
              <div>
                <span className="text-slate-500 flex items-center gap-1"><Cpu size={12} /> {locale === 'he' ? 'רמת AI' : 'AI Tier'}</span>
                <div className="mt-1 text-white font-medium">{(license.ai_tier as string) || 'NONE'}</div>
              </div>
              <div>
                <span className="text-slate-500">{locale === 'he' ? 'תקציב יומי AI' : 'AI Daily Budget'}</span>
                <div className="mt-1 text-white font-medium">{(license.ai_daily_budget as number) || 0} {locale === 'he' ? 'שאילתות' : 'queries'}</div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Save */}
      <div className="flex items-center gap-4">
        <button
          onClick={handleSave}
          className="px-6 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium transition-colors"
        >
          {t('settings.save')}
        </button>
        {saved && (
          <span className="text-green-400 text-sm flex items-center gap-1.5">
            <CheckCircle size={16} /> {t('settings.saved')}
          </span>
        )}
      </div>
    </div>
  )
}
