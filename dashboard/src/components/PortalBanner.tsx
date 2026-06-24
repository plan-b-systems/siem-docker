'use client'

import { useEffect, useState } from 'react'
import { AlertTriangle, X } from 'lucide-react'
import { useLanguage } from '@/components/LanguageProvider'

type PortalStatus = {
  bootstrapped: boolean | null
  authenticated: boolean | null
  failed_bootstrap_count?: number
  last_check?: string | null
  source?: string
}

export default function PortalBanner() {
  const { t } = useLanguage()
  const [s, setS] = useState<PortalStatus | null>(null)
  const [dismissed, setDismissed] = useState(false)

  useEffect(() => {
    let alive = true
    const load = async () => {
      try {
        const r = await fetch('/api/portal-status', { cache: 'no-store' })
        if (r.ok && alive) setS(await r.json())
      } catch {
        /* ignore — stay silent rather than false-alarm */
      }
    }
    load()
    const id = setInterval(load, 60_000)
    return () => {
      alive = false
      clearInterval(id)
    }
  }, [])

  // Show ONLY when we positively know it is not bootstrapped.
  // null (unknown / legacy / file missing) => stay silent to avoid false alarms.
  if (dismissed || !s || s.bootstrapped !== false) return null

  const fails = s.failed_bootstrap_count ?? 0
  return (
    <div className="sticky top-0 z-40 bg-red-700 text-white px-6 py-3 flex items-center gap-3 shadow-lg">
      <AlertTriangle className="h-5 w-5 shrink-0 animate-pulse" />
      <div className="text-sm flex-1">
        <span className="font-bold uppercase tracking-wide">{t('portal.notConnected')}</span>
        <span className="opacity-90 ml-2 rtl:ml-0 rtl:mr-2">{t('portal.notConnectedDetail')}</span>
        {fails > 0 && (
          <span className="ml-2 rtl:ml-0 rtl:mr-2 font-mono bg-red-900/60 rounded px-1.5 py-0.5">
            {fails} failed attempt{fails === 1 ? '' : 's'}
          </span>
        )}
      </div>
      <button
        type="button"
        onClick={() => setDismissed(true)}
        aria-label="Dismiss"
        className="shrink-0 rounded p-1 hover:bg-red-900/60 transition-colors"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  )
}
