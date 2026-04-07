'use client'

import { useState } from 'react'
import Link from 'next/link'
import Image from 'next/image'
import { usePathname } from 'next/navigation'
import {
  LayoutDashboard,
  ShieldAlert,
  Search,
  Server,
  Settings,
  ChevronLeft,
  ChevronRight,
  LogOut,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useLanguage } from './LanguageProvider'
import type { TranslationKey } from '@/lib/i18n'

const navItems: { href: string; labelKey: TranslationKey; icon: typeof LayoutDashboard }[] = [
  { href: '/overview', labelKey: 'nav.overview', icon: LayoutDashboard },
  { href: '/threats', labelKey: 'nav.threats', icon: ShieldAlert },
  { href: '/forensics', labelKey: 'nav.forensics', icon: Search },
  { href: '/sources', labelKey: 'nav.sources', icon: Server },
]

export default function Sidebar() {
  const [collapsed, setCollapsed] = useState(false)
  const pathname = usePathname()
  const { t, dir } = useLanguage()
  const isRtl = dir === 'rtl'

  async function handleLogout() {
    await fetch('/api/auth/login', { method: 'DELETE' })
    window.location.href = '/login'
  }

  return (
    <aside
      className={cn(
        'fixed top-0 h-screen bg-slate-950 flex flex-col transition-all duration-200 z-50',
        isRtl ? 'right-0 border-l border-slate-800' : 'left-0 border-r border-slate-800',
        collapsed ? 'w-16' : 'w-60'
      )}
    >
      {/* Logo */}
      <div className={cn('flex items-center border-b border-slate-800 h-16 px-4', collapsed && 'justify-center')}>
        {collapsed ? (
          <Image src="/logo-small.png" alt="Plan-B" width={32} height={11} />
        ) : (
          <Image src="/logo-dark.png" alt="Plan-B Systems" width={160} height={45} priority />
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 py-4 space-y-1 px-2">
        {navItems.map(({ href, labelKey, icon: Icon }) => {
          const active = pathname === href || pathname.startsWith(href + '/')
          const label = t(labelKey)
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors',
                active
                  ? 'bg-blue-600/15 text-blue-400'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/50',
                collapsed && 'justify-center px-0'
              )}
              title={collapsed ? label : undefined}
            >
              <Icon size={20} className="shrink-0" />
              {!collapsed && <span>{label}</span>}
            </Link>
          )
        })}
      </nav>

      {/* Bottom */}
      <div className="border-t border-slate-800 py-3 px-2 space-y-1">
        <Link
          href="/settings"
          className={cn(
            'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors',
            pathname === '/settings'
              ? 'bg-blue-600/15 text-blue-400'
              : 'text-slate-400 hover:text-white hover:bg-slate-800/50',
            collapsed && 'justify-center px-0'
          )}
          title={collapsed ? 'Settings' : undefined}
        >
          <Settings size={20} className="shrink-0" />
          {!collapsed && <span>{t('nav.settings')}</span>}
        </Link>

        <button
          onClick={handleLogout}
          className={cn(
            'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors w-full text-slate-400 hover:text-red-400 hover:bg-slate-800/50',
            collapsed && 'justify-center px-0'
          )}
          title={collapsed ? t('nav.logout') : undefined}
        >
          <LogOut size={20} className="shrink-0" />
          {!collapsed && <span>{t('nav.logout')}</span>}
        </button>

        {/* Collapse toggle */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className={cn(
            'flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors w-full text-slate-500 hover:text-slate-300',
            collapsed && 'justify-center px-0'
          )}
        >
          {collapsed
            ? (isRtl ? <ChevronLeft size={18} /> : <ChevronRight size={18} />)
            : (isRtl ? <ChevronRight size={18} /> : <ChevronLeft size={18} />)
          }
          {!collapsed && <span className="text-xs">{t('nav.collapse')}</span>}
        </button>
      </div>
    </aside>
  )
}
