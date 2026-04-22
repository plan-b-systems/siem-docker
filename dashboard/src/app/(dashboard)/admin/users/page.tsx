'use client'

import { useEffect, useState } from 'react'
import {
  UserPlus, KeyRound, ShieldOff, Unlock, LogOut as LogOutIcon, Trash2, Mail, Copy, Check, X, Loader2,
} from 'lucide-react'

type PublicUser = {
  id: string
  username: string
  email: string | null
  full_name: string | null
  role: 'admin' | 'user'
  must_change_password: boolean
  mfa_enrolled: boolean
  is_disabled: boolean
  is_locked: boolean
  last_login_at: number | null
  last_login_ip: string | null
  created_at: number
}

function fmt(ts: number | null) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString()
}

export default function AdminUsersPage() {
  const [users, setUsers] = useState<PublicUser[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const [tempCredential, setTempCredential] = useState<{ username: string; password: string } | null>(null)

  async function load() {
    setLoading(true)
    try {
      const res = await fetch('/api/admin/users')
      const data = await res.json()
      if (res.ok) setUsers(data.users)
      else setError(data.error || 'Failed to load')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  async function callAction(url: string, method = 'POST') {
    const res = await fetch(url, { method })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(data.error || `${method} ${url} failed`)
    return data
  }

  async function resetPw(u: PublicUser) {
    if (!confirm(`Reset password for ${u.username}? All their sessions will be revoked.`)) return
    try {
      const data = await callAction(`/api/admin/users/${u.id}/reset-password`)
      if (data.temp_password) setTempCredential({ username: u.username, password: data.temp_password })
      else alert(`Password reset — temporary password emailed to ${u.email}.`)
    } catch (e) {
      alert(String(e))
    }
  }
  async function clearMfa(u: PublicUser) {
    if (!confirm(`Clear MFA for ${u.username}? They'll be prompted to re-enrol on next login.`)) return
    try { await callAction(`/api/admin/users/${u.id}/clear-mfa`); load() } catch (e) { alert(String(e)) }
  }
  async function unlock(u: PublicUser) {
    try { await callAction(`/api/admin/users/${u.id}/unlock`); load() } catch (e) { alert(String(e)) }
  }
  async function revokeSessions(u: PublicUser) {
    if (!confirm(`Revoke all sessions for ${u.username}?`)) return
    try { await callAction(`/api/admin/users/${u.id}/revoke-sessions`); load() } catch (e) { alert(String(e)) }
  }
  async function toggleDisable(u: PublicUser) {
    const action = u.is_disabled ? 'enable' : 'disable'
    if (!confirm(`${action === 'disable' ? 'Disable' : 'Enable'} ${u.username}?`)) return
    try {
      const res = await fetch(`/api/admin/users/${u.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ is_disabled: !u.is_disabled }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error)
      load()
    } catch (e) { alert(String(e)) }
  }
  async function del(u: PublicUser) {
    if (!confirm(`Delete ${u.username}? This cannot be undone.`)) return
    try {
      const res = await fetch(`/api/admin/users/${u.id}`, { method: 'DELETE' })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error)
      load()
    } catch (e) { alert(String(e)) }
  }

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-semibold text-white">Users</h1>
          <p className="text-sm text-slate-400">Accounts allowed to sign in to this dashboard.</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 h-10 px-4 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium"
        >
          <UserPlus size={16} /> Add user
        </button>
      </div>

      {loading && <div className="flex items-center gap-2 text-slate-400 text-sm"><Loader2 size={16} className="animate-spin" /> Loading…</div>}
      {error && <div className="text-sm text-red-400 bg-red-500/10 rounded-lg p-3 mb-4">{error}</div>}

      {!loading && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-950 text-slate-400 text-xs uppercase">
              <tr>
                <th className="text-left px-4 py-3">User</th>
                <th className="text-left px-4 py-3">Role</th>
                <th className="text-left px-4 py-3">State</th>
                <th className="text-left px-4 py-3">Last login</th>
                <th className="text-right px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {users.map(u => (
                <tr key={u.id} className="hover:bg-slate-800/30">
                  <td className="px-4 py-3">
                    <div className="text-white font-medium">{u.username}</div>
                    <div className="text-xs text-slate-500">{u.full_name || ''}{u.email ? ` · ${u.email}` : ''}</div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs ${u.role === 'admin' ? 'bg-purple-500/20 text-purple-300' : 'bg-slate-700 text-slate-300'}`}>{u.role}</span>
                  </td>
                  <td className="px-4 py-3 space-x-1">
                    {u.is_disabled && <span className="px-2 py-0.5 rounded text-xs bg-slate-700 text-slate-400">disabled</span>}
                    {u.is_locked && <span className="px-2 py-0.5 rounded text-xs bg-amber-500/20 text-amber-300">locked</span>}
                    {u.must_change_password && <span className="px-2 py-0.5 rounded text-xs bg-blue-500/20 text-blue-300">must change pw</span>}
                    {u.mfa_enrolled
                      ? <span className="px-2 py-0.5 rounded text-xs bg-emerald-500/20 text-emerald-300">MFA on</span>
                      : <span className="px-2 py-0.5 rounded text-xs bg-amber-500/20 text-amber-300">MFA off</span>}
                  </td>
                  <td className="px-4 py-3 text-slate-400 text-xs">
                    <div>{fmt(u.last_login_at)}</div>
                    <div>{u.last_login_ip || ''}</div>
                  </td>
                  <td className="px-4 py-3 text-right space-x-1 whitespace-nowrap">
                    <button onClick={() => resetPw(u)} title="Reset password" className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white"><KeyRound size={14} /></button>
                    <button onClick={() => clearMfa(u)} title="Clear MFA" className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white"><ShieldOff size={14} /></button>
                    {u.is_locked && <button onClick={() => unlock(u)} title="Unlock" className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white"><Unlock size={14} /></button>}
                    <button onClick={() => revokeSessions(u)} title="Revoke sessions" className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white"><LogOutIcon size={14} /></button>
                    <button onClick={() => toggleDisable(u)} title={u.is_disabled ? 'Enable' : 'Disable'} className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white">{u.is_disabled ? <Check size={14} /> : <X size={14} />}</button>
                    <button onClick={() => del(u)} title="Delete" className="p-1.5 rounded hover:bg-red-500/20 text-slate-400 hover:text-red-400"><Trash2 size={14} /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && <CreateUserModal onClose={() => setShowCreate(false)} onCreated={(cred) => { setShowCreate(false); if (cred) setTempCredential(cred); load() }} />}
      {tempCredential && <TempCredentialModal cred={tempCredential} onClose={() => setTempCredential(null)} />}
    </div>
  )
}

function CreateUserModal({ onClose, onCreated }: { onClose: () => void; onCreated: (cred: { username: string; password: string } | null) => void }) {
  const [username, setUsername] = useState('')
  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [role, setRole] = useState<'admin' | 'user'>('user')
  const [sendEmail, setSendEmail] = useState(false)
  const [password, setPassword] = useState('')
  const [useGenerated, setUseGenerated] = useState(true)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(''); setLoading(true)
    try {
      const body: Record<string, unknown> = { username, full_name: fullName || undefined, email: email || undefined, role, send_email: sendEmail }
      if (!useGenerated) body.password = password
      const res = await fetch('/api/admin/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      const data = await res.json()
      if (!res.ok) setError(data.error || 'Create failed')
      else onCreated(data.initial_password ? { username, password: data.initial_password } : null)
    } catch {
      setError('Connection error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 w-full max-w-md">
        <h2 className="text-lg font-semibold text-white mb-4">Add user</h2>
        <form onSubmit={onSubmit} className="space-y-3">
          <input required value={username} onChange={e=>setUsername(e.target.value)} placeholder="Username" className="w-full h-10 px-3 rounded-lg bg-slate-800 border border-slate-700 text-white text-sm" />
          <input value={fullName} onChange={e=>setFullName(e.target.value)} placeholder="Full name (optional)" className="w-full h-10 px-3 rounded-lg bg-slate-800 border border-slate-700 text-white text-sm" />
          <input type="email" value={email} onChange={e=>setEmail(e.target.value)} placeholder="Email (optional)" className="w-full h-10 px-3 rounded-lg bg-slate-800 border border-slate-700 text-white text-sm" />
          <select value={role} onChange={e=>setRole(e.target.value as 'admin' | 'user')} className="w-full h-10 px-3 rounded-lg bg-slate-800 border border-slate-700 text-white text-sm">
            <option value="user">User</option>
            <option value="admin">Admin</option>
          </select>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input type="checkbox" checked={useGenerated} onChange={e=>setUseGenerated(e.target.checked)} /> Generate a random password (recommended)
          </label>
          {!useGenerated && (
            <input type="password" value={password} onChange={e=>setPassword(e.target.value)} placeholder="Initial password" className="w-full h-10 px-3 rounded-lg bg-slate-800 border border-slate-700 text-white text-sm" />
          )}
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input type="checkbox" checked={sendEmail} onChange={e=>setSendEmail(e.target.checked)} disabled={!email} /> Email the initial credentials
          </label>
          {error && <p className="text-sm text-red-400">{error}</p>}
          <div className="flex items-center justify-end gap-2 pt-2">
            <button type="button" onClick={onClose} className="h-10 px-4 rounded-lg text-slate-300 hover:bg-slate-800 text-sm">Cancel</button>
            <button type="submit" disabled={loading || !username} className="h-10 px-4 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm disabled:opacity-50">{loading ? 'Creating…' : 'Create'}</button>
          </div>
        </form>
      </div>
    </div>
  )
}

function TempCredentialModal({ cred, onClose }: { cred: { username: string; password: string }; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    await navigator.clipboard.writeText(cred.password)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 w-full max-w-md">
        <h2 className="text-lg font-semibold text-white mb-2">Temporary password for {cred.username}</h2>
        <p className="text-sm text-slate-400 mb-4">This password is shown once. The user will be required to change it on first login and enrol MFA.</p>
        <div className="flex items-center gap-2 bg-slate-800 rounded-lg p-3 mb-4">
          <code className="flex-1 text-emerald-300 font-mono text-sm break-all">{cred.password}</code>
          <button onClick={copy} className="p-2 rounded hover:bg-slate-700 text-slate-400 hover:text-white" title="Copy">
            {copied ? <Check size={16} className="text-emerald-400" /> : <Copy size={16} />}
          </button>
        </div>
        <div className="flex justify-end">
          <button onClick={onClose} className="h-10 px-4 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm">Done</button>
        </div>
      </div>
    </div>
  )
}
