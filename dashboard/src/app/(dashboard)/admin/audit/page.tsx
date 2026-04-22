'use client'

import { useEffect, useState } from 'react'
import { Loader2, RefreshCw } from 'lucide-react'

type AuditEntry = {
  id: number
  user_id: string | null
  actor_username: string | null
  action: string
  target_type: string | null
  target_id: string | null
  ip: string | null
  user_agent: string | null
  success: number
  message: string | null
  created_at: number
}

function fmt(ts: number) {
  return new Date(ts).toLocaleString()
}

export default function AdminAuditPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('')

  async function load() {
    setLoading(true)
    try {
      const res = await fetch('/api/admin/audit?limit=500')
      const data = await res.json()
      if (res.ok) setEntries(data.entries)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const filtered = entries.filter(e => {
    if (!filter) return true
    const hay = `${e.actor_username || ''} ${e.action} ${e.message || ''} ${e.ip || ''}`.toLowerCase()
    return hay.includes(filter.toLowerCase())
  })

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-semibold text-white">Audit log</h1>
          <p className="text-sm text-slate-400">Authentication and admin actions (last 500 entries).</p>
        </div>
        <div className="flex items-center gap-2">
          <input
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter…"
            className="h-10 px-3 rounded-lg bg-slate-800 border border-slate-700 text-white text-sm"
          />
          <button onClick={load} className="p-2 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white" title="Refresh">
            <RefreshCw size={16} />
          </button>
        </div>
      </div>

      {loading && <div className="flex items-center gap-2 text-slate-400 text-sm"><Loader2 size={16} className="animate-spin" /> Loading…</div>}

      {!loading && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-950 text-slate-400 text-xs uppercase">
              <tr>
                <th className="text-left px-4 py-3 whitespace-nowrap">When</th>
                <th className="text-left px-4 py-3">Action</th>
                <th className="text-left px-4 py-3">Actor</th>
                <th className="text-left px-4 py-3">IP</th>
                <th className="text-left px-4 py-3">Result</th>
                <th className="text-left px-4 py-3">Detail</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {filtered.map(e => (
                <tr key={e.id} className="hover:bg-slate-800/30">
                  <td className="px-4 py-2 text-xs text-slate-400 whitespace-nowrap">{fmt(e.created_at)}</td>
                  <td className="px-4 py-2 font-mono text-xs text-slate-200">{e.action}</td>
                  <td className="px-4 py-2 text-slate-300">{e.actor_username || '—'}</td>
                  <td className="px-4 py-2 text-xs text-slate-400 font-mono">{e.ip || ''}</td>
                  <td className="px-4 py-2">
                    {e.success
                      ? <span className="px-2 py-0.5 rounded text-xs bg-emerald-500/20 text-emerald-300">ok</span>
                      : <span className="px-2 py-0.5 rounded text-xs bg-red-500/20 text-red-300">fail</span>}
                  </td>
                  <td className="px-4 py-2 text-xs text-slate-400">{e.message || ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {filtered.length === 0 && (
            <div className="px-4 py-8 text-center text-sm text-slate-500">No entries.</div>
          )}
        </div>
      )}
    </div>
  )
}
