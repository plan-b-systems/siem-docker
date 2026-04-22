'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import Image from 'next/image'
import Link from 'next/link'

type Stage = 'password' | 'mfa'

export default function LoginPage() {
  const [stage, setStage] = useState<Stage>('password')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [tempToken, setTempToken] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const router = useRouter()

  function onPostLogin(data: { must_change_password?: boolean; mfa_enrolled?: boolean }) {
    if (data.must_change_password) {
      router.push('/change-password')
    } else if (!data.mfa_enrolled) {
      router.push('/enroll-mfa')
    } else {
      router.push('/overview')
    }
    router.refresh()
  }

  async function submitPassword(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.error || 'Login failed')
      } else if (data.stage === 'mfa_required') {
        setTempToken(data.temp_token)
        setStage('mfa')
      } else if (data.stage === 'authenticated') {
        onPostLogin(data)
      }
    } catch {
      setError('Connection error')
    } finally {
      setLoading(false)
    }
  }

  async function submitMfa(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await fetch('/api/auth/verify-mfa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ temp_token: tempToken, totp_code: totpCode }),
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.error || 'MFA verification failed')
      } else if (data.stage === 'authenticated') {
        onPostLogin(data)
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
          <Image src="/logo-dark.png" alt="Plan-B Systems" width={280} height={80} priority />
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 shadow-2xl">
          <h1 className="text-xl font-semibold text-white text-center mb-2">SIEM Dashboard</h1>
          <p className="text-sm text-slate-400 text-center mb-6">
            {stage === 'password' ? 'Sign in to continue' : 'Enter the 6-digit code from your authenticator app'}
          </p>

          {stage === 'password' ? (
            <form onSubmit={submitPassword} className="space-y-4">
              <input
                type="text"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Username"
                className="w-full h-11 px-4 rounded-lg bg-slate-800 border border-slate-700 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                autoFocus
              />
              <input
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Password"
                className="w-full h-11 px-4 rounded-lg bg-slate-800 border border-slate-700 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              {error && <p className="text-sm text-red-400 text-center">{error}</p>}
              <button
                type="submit"
                disabled={loading || !username || !password}
                className="w-full h-11 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? 'Signing in…' : 'Sign in'}
              </button>
              <div className="text-center">
                <Link href="/forgot-password" className="text-xs text-slate-400 hover:text-slate-200">
                  Forgot password?
                </Link>
              </div>
            </form>
          ) : (
            <form onSubmit={submitMfa} className="space-y-4">
              <input
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9]*"
                maxLength={6}
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/[^0-9]/g, ''))}
                placeholder="123456"
                className="w-full h-11 px-4 rounded-lg bg-slate-800 border border-slate-700 text-white text-center tracking-[0.3em] font-mono text-lg placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                autoFocus
              />
              {error && <p className="text-sm text-red-400 text-center">{error}</p>}
              <button
                type="submit"
                disabled={loading || totpCode.length !== 6}
                className="w-full h-11 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? 'Verifying…' : 'Verify'}
              </button>
              <button
                type="button"
                onClick={() => { setStage('password'); setTotpCode(''); setTempToken(''); setError('') }}
                className="w-full text-xs text-slate-400 hover:text-slate-200"
              >
                Back to sign-in
              </button>
            </form>
          )}
        </div>
        <p className="text-xs text-slate-600 text-center mt-6">Plan-B Systems SIEM v2</p>
      </div>
    </div>
  )
}
