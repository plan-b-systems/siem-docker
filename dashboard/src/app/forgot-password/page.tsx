'use client'

import { useState } from 'react'
import Image from 'next/image'
import Link from 'next/link'

export default function ForgotPasswordPage() {
  const [identifier, setIdentifier] = useState('')
  const [submitted, setSubmitted] = useState(false)
  const [loading, setLoading] = useState(false)

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    try {
      await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: identifier, email: identifier }),
      })
      setSubmitted(true)
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
          <h1 className="text-xl font-semibold text-white text-center mb-2">Reset password</h1>
          {submitted ? (
            <>
              <p className="text-sm text-slate-400 text-center mb-4">
                If an account matches, a reset link has been sent. Check your email. If your account has no email on file, contact your administrator — the reset token is recorded in the server log for SSH-assisted recovery.
              </p>
              <Link href="/login" className="block w-full text-center text-sm text-blue-400 hover:text-blue-300">
                Back to sign-in
              </Link>
            </>
          ) : (
            <>
              <p className="text-sm text-slate-400 text-center mb-6">Enter your username or email and we&apos;ll send a reset link (if an account exists).</p>
              <form onSubmit={onSubmit} className="space-y-4">
                <input
                  type="text"
                  value={identifier}
                  onChange={(e) => setIdentifier(e.target.value)}
                  placeholder="Username or email"
                  className="w-full h-11 px-4 rounded-lg bg-slate-800 border border-slate-700 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  autoFocus
                />
                <button type="submit" disabled={loading || !identifier} className="w-full h-11 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium disabled:opacity-50 disabled:cursor-not-allowed">
                  {loading ? 'Sending…' : 'Send reset link'}
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
