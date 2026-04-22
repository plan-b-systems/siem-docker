import crypto from 'crypto'
import { NextResponse } from 'next/server'
import { getDb } from '@/lib/auth-db'
import { findUserById, setPassword, updateUserFields } from '@/lib/auth-users'
import { validatePasswordPolicy, isPasswordReused } from '@/lib/auth-password'
import { revokeAllSessionsForUser } from '@/lib/auth-session'
import { audit } from '@/lib/auth-audit'
import { getClientIp } from '@/lib/auth-require'

export async function POST(req: Request) {
  const ip = getClientIp(req)
  const userAgent = req.headers.get('user-agent')

  let body: { token?: string; new_password?: string }
  try {
    body = await req.json()
  } catch {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 })
  }
  const token = (body.token || '').trim()
  const newPassword = body.new_password || ''
  if (!token || !newPassword) return NextResponse.json({ error: 'Token and new password required' }, { status: 400 })

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex')
  const db = getDb()
  const row = db.prepare(`
    SELECT id, user_id, expires_at, used_at FROM password_reset_tokens WHERE token_hash = ?
  `).get(tokenHash) as { id: string; user_id: string; expires_at: number; used_at: number | null } | undefined

  if (!row) return NextResponse.json({ error: 'Invalid or expired token' }, { status: 400 })
  if (row.used_at) return NextResponse.json({ error: 'Token has already been used' }, { status: 400 })
  if (row.expires_at <= Date.now()) return NextResponse.json({ error: 'Token has expired' }, { status: 400 })

  const user = findUserById(row.user_id)
  if (!user || user.is_disabled) return NextResponse.json({ error: 'User unavailable' }, { status: 400 })

  const policy = validatePasswordPolicy(newPassword, user.username)
  if (!policy.ok) return NextResponse.json({ error: policy.reason }, { status: 400 })

  if (await isPasswordReused(user.id, newPassword)) {
    return NextResponse.json({ error: 'Password was used recently. Choose a different one.' }, { status: 400 })
  }

  await setPassword(user.id, newPassword)
  updateUserFields(user.id, { failed_attempts: 0, locked_until: null })
  db.prepare('UPDATE password_reset_tokens SET used_at = ? WHERE id = ?').run(Date.now(), row.id)
  revokeAllSessionsForUser(user.id)

  audit({ userId: user.id, actorUsername: user.username, action: 'auth.password_reset_completed', ip, userAgent, success: true })
  return NextResponse.json({ success: true })
}
