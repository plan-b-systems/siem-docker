import crypto from 'crypto'
import { NextResponse } from 'next/server'
import { findUserByUsername } from '@/lib/auth-users'
import { getDb } from '@/lib/auth-db'
import { ensureBootstrapped } from '@/lib/auth-bootstrap'
import { audit } from '@/lib/auth-audit'
import { sendEmail, isEmailConfigured } from '@/lib/auth-email'
import { getClientIp } from '@/lib/auth-require'

const TOKEN_TTL_MS = 30 * 60 * 1000

function buildResetLink(token: string, host: string): string {
  const publicUrl = process.env.PUBLIC_URL || `http://${host}`
  return `${publicUrl.replace(/\/$/, '')}/reset-password?token=${encodeURIComponent(token)}`
}

export async function POST(req: Request) {
  await ensureBootstrapped()
  const ip = getClientIp(req)
  const userAgent = req.headers.get('user-agent')

  let body: { username?: string; email?: string }
  try {
    body = await req.json()
  } catch {
    return NextResponse.json({ ok: true })
  }
  const identifier = (body.username || body.email || '').trim()
  if (!identifier) return NextResponse.json({ ok: true })

  // Always respond 200 regardless of whether the user exists — prevents enumeration.
  const user = findUserByUsername(identifier) ||
    (body.email ? (getDb().prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE').get(identifier) as { id: string; username: string; email: string | null } | undefined) : null)

  if (!user) {
    audit({ actorUsername: identifier, action: 'auth.forgot_password_unknown', ip, userAgent, success: false })
    return NextResponse.json({ ok: true })
  }

  // Invalidate any outstanding tokens for this user.
  const db = getDb()
  db.prepare('DELETE FROM password_reset_tokens WHERE user_id = ? AND used_at IS NULL').run(user.id)

  const tokenBytes = crypto.randomBytes(32)
  const token = tokenBytes.toString('base64url')
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex')
  const id = crypto.randomUUID()
  const now = Date.now()
  db.prepare(`
    INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(id, user.id, tokenHash, now + TOKEN_TTL_MS, now)

  const host = req.headers.get('host') || 'localhost:3000'
  const link = buildResetLink(token, host)
  const subject = 'Plan-B SIEM — Password reset'
  const text = `A password reset was requested for user "${user.username}".\n\nClick the link below to reset your password. It expires in 30 minutes:\n\n${link}\n\nIf you did not request this, ignore this email.`
  const html = `<p>A password reset was requested for user <strong>${user.username}</strong>.</p><p><a href="${link}">Reset your password</a> (link expires in 30 minutes).</p><p>If you did not request this, ignore this email.</p>`

  let delivered = false
  if (user.email && isEmailConfigured()) {
    const result = await sendEmail(user.email, subject, html, text)
    delivered = result.sent
  } else {
    // No email on file, or SMTP unset — token is logged for SSH-assisted retrieval.
    console.warn(`[forgot-password] Token generated for user ${user.username} but not emailed. Reset link:\n${link}`)
  }

  audit({
    userId: user.id,
    actorUsername: user.username,
    action: 'auth.forgot_password_requested',
    ip,
    userAgent,
    success: true,
    message: delivered ? 'email_sent' : 'no_email_available',
  })
  return NextResponse.json({ ok: true })
}
