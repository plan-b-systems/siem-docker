'use client'

import { Suspense, useEffect, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import Image from 'next/image'
import Link from 'next/link'

function ResetInner() {
  const search = useSearchParams()
  const token = search.get('token') || ''
  const router = useRouter()
  const [newPw, setNewPw] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [done, setDone] = useState(false)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!token) setError('Missing token')
  }, [token])

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    if (newPw !== confirm) return setError('Passwords do not match')
    setLoading(true)
    try {
      const res = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, new_password: newPw }),
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.error || 'Reset failed')
      } else {
        setDone(true)
        setTimeout(() => router.push('/login'), 1500)
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
          <h1 className="text-xl font-semibold text-white text-center mb-2">Choose a new password</h1>
          {done ? (
            <p className="text-sm text-green-400 text-center">Password updated. Redirecting to sign-in…</p>
          ) : (
            <>
              <p className="text-sm text-slate-400 text-center mb-6">Minimum 12 characters, with upper, lower, and a digit.</p>
              <form onSubmit={onSubmit} className="space-y-4">
                <input type="password" placeholder="New password" value={newPw} onChange={e=>setNewPw(e.target.value)} className="w-full h-11 px-4 rounded-lg bg-slate-800 border border-slate-700 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500" autoFocus />
                <input type="password" placeholder="Confirm new password" value={confirm} onChange={e=>setConfirm(e.target.value)} className="w-full h-11 px-4 rounded-lg bg-slate-800 border border-slate-700 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500" />
                {error && <p className="text-sm text-red-400 text-center">{error}</p>}
                <button type="submit" disabled={loading || !newPw || !confirm || !token} className="w-full h-11 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium disabled:opacity-50 disabled:cursor-not-allowed">
                  {loading ? 'Updating…' : 'Reset password'}
                </button>
                <Link href="/login" className="block w-full text-center text-xs text-slate-400 hover:text-slate-200">
                  Back to sign-in
                </Link>
              </form>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

export default function ResetPasswordPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-slate-950" />}>
      <ResetInner />
    </Suspense>
  )
}
