'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import Image from 'next/image'

export default function EnrollMfaPage() {
  const [secret, setSecret] = useState('')
  const [qr, setQr] = useState('')
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [confirming, setConfirming] = useState(false)
  const router = useRouter()

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch('/api/auth/enroll-mfa', { method: 'POST' })
        const data = await res.json()
        if (!res.ok) {
          setError(data.error || 'Failed to start enrolment')
        } else {
          setSecret(data.secret)
          setQr(data.qr_data_url)
        }
      } catch {
        setError('Connection error')
      } finally {
        setLoading(false)
      }
    })()
  }, [])

  async function onConfirm(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setConfirming(true)
    try {
      const res = await fetch('/api/auth/confirm-mfa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ totp_code: code }),
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.error || 'Invalid code')
      } else {
        router.push('/overview')
        router.refresh()
      }
    } catch {
      setError('Connection error')
    } finally {
      setConfirming(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950">
      <div className="w-full max-w-md p-8">
        <div className="flex justify-center mb-8">
          <Image src="/logo-dark.png" alt="Plan-B Systems" width={240} height={70} priority />
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 shadow-2xl">
          <h1 className="text-xl font-semibold text-white text-center mb-2">Set up two-factor authentication</h1>
          <p className="text-sm text-slate-400 text-center mb-4">Scan the QR code in your authenticator app, then enter the 6-digit code it shows.</p>

          {loading && <p className="text-center text-slate-500 text-sm">Preparing secret…</p>}

          {qr && (
            <div className="flex flex-col items-center gap-3 mb-4">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img src={qr} alt="TOTP QR code" width={220} height={220} className="rounded-lg bg-white p-2" />
              <details className="text-xs text-slate-500 select-all">
                <summary className="cursor-pointer">Can&apos;t scan? Enter manually</summary>
                <div className="mt-2 font-mono break-all bg-slate-800 rounded p-2">{secret}</div>
              </details>
            </div>
          )}

          <form onSubmit={onConfirm} className="space-y-4">
            <input
              type="text"
              inputMode="numeric"
              pattern="[0-9]*"
              maxLength={6}
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/[^0-9]/g, ''))}
              placeholder="123456"
              className="w-full h-11 px-4 rounded-lg bg-slate-800 border border-slate-700 text-white text-center tracking-[0.3em] font-mono text-lg placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            {error && <p className="text-sm text-red-400 text-center">{error}</p>}
            <button type="submit" disabled={confirming || code.length !== 6 || !secret} className="w-full h-11 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium disabled:opacity-50 disabled:cursor-not-allowed">
              {confirming ? 'Confirming…' : 'Enable MFA'}
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
