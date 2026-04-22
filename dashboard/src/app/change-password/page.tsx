'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import Image from 'next/image'

export default function ChangePasswordPage() {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const router = useRouter()

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    if (next !== confirm) return setError('New passwords do not match')
    setLoading(true)
    try {
      const res = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: current, new_password: next }),
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.error || 'Change failed')
      } else {
        // After changing, enrolment is the next forced step (handled by the dashboard layout).
        router.push('/overview')
        router.refresh()
      }
    } catch {
      setError('Connection error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950">
      <div className="w-full max-w-md p-8">
        <div className="flex justify-center mb-8">
          <Image src="/logo-dark.png" alt="Plan-B Systems" width={240} height={70} priority />
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 shadow-2xl">
          <h1 className="text-xl font-semibold text-white text-center mb-2">Change password</h1>
          <p className="text-sm text-slate-400 text-center mb-6">Minimum 12 characters, with upper, lower, and a digit.</p>
          <form onSubmit={onSubmit} className="space-y-4">
            <input type="password" placeholder="Current password" value={current} onChange={e=>setCurrent(e.target.value)} className="w-full h-11 px-4 rounded-lg bg-slate-800 border border-slate-700 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500" autoFocus />
            <input type="password" placeholder="New password" value={next} onChange={e=>setNext(e.target.value)} className="w-full h-11 px-4 rounded-lg bg-slate-800 border border-slate-700 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500" />
            <input type="password" placeholder="Confirm new password" value={confirm} onChange={e=>setConfirm(e.target.value)} className="w-full h-11 px-4 rounded-lg bg-slate-800 border border-slate-700 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500" />
            {error && <p className="text-sm text-red-400 text-center">{error}</p>}
            <button type="submit" disabled={loading || !current || !next || !confirm} className="w-full h-11 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium disabled:opacity-50 disabled:cursor-not-allowed">
              {loading ? 'Updating…' : 'Change password'}
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
