import crypto from 'crypto'
import { NextResponse } from 'next/server'
import { requireAdmin, getClientIp } from '@/lib/auth-require'
import { createUser, listUsers } from '@/lib/auth-users'
import { validatePasswordPolicy } from '@/lib/auth-password'
import { audit } from '@/lib/auth-audit'
import { sendEmail, isEmailConfigured } from '@/lib/auth-email'

export async function GET() {
  const auth = await requireAdmin()
  if ('errorResponse' in auth) return auth.errorResponse
  return NextResponse.json({ users: listUsers() })
}

function generatePassword(): string {
  // 16 random bytes → ~21 base64 chars, plenty of entropy and meets policy.
  return crypto.randomBytes(12).toString('base64').replace(/[+/=]/g, '') + 'Aa1'
}

export async function POST(req: Request) {
  const auth = await requireAdmin()
  if ('errorResponse' in auth) return auth.errorResponse
  const ip = getClientIp(req)
  const userAgent = req.headers.get('user-agent')

  let body: { username?: string; email?: string; full_name?: string; role?: 'admin' | 'user'; password?: string; send_email?: boolean }
  try {
    body = await req.json()
  } catch {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 })
  }

  const username = (body.username || '').trim()
  if (!username || !/^[a-zA-Z0-9._-]{3,32}$/.test(username)) {
    return NextResponse.json({ error: 'Username must be 3–32 chars, alphanumeric plus . _ -' }, { status: 400 })
  }

  let initialPassword = body.password?.trim() || ''
  let generated = false
  if (!initialPassword) {
    initialPassword = generatePassword()
    generated = true
  } else {
    const policy = validatePasswordPolicy(initialPassword, username)
    if (!policy.ok) return NextResponse.json({ error: policy.reason }, { status: 400 })
  }

  try {
    const user = await createUser({
      username,
      password: initialPassword,
      email: body.email?.trim() || undefined,
      full_name: body.full_name?.trim() || undefined,
      role: body.role === 'admin' ? 'admin' : 'user',
      must_change_password: true,
    })
    audit({
      userId: auth.user.id,
      actorUsername: auth.user.username,
      action: 'admin.user_created',
      targetType: 'user',
      targetId: user.id,
      ip,
      userAgent,
      success: true,
      message: `created ${username} as ${user.role}`,
    })

    let emailSent = false
    if (body.send_email && user.email && isEmailConfigured()) {
      const text = `A Plan-B SIEM dashboard account has been created for you.\n\nUsername: ${username}\nInitial password: ${initialPassword}\n\nYou will be required to change this password and enrol MFA on your first login.`
      const html = `<p>A Plan-B SIEM dashboard account has been created for you.</p><ul><li>Username: <strong>${username}</strong></li><li>Initial password: <code>${initialPassword}</code></li></ul><p>You will be required to change this password and enrol MFA on your first login.</p>`
      const r = await sendEmail(user.email, 'Plan-B SIEM — Your new account', html, text)
      emailSent = r.sent
    }

    return NextResponse.json({
      user,
      // Return the generated password ONCE so the admin can copy it if email is off.
      initial_password: generated || !emailSent ? initialPassword : undefined,
      email_sent: emailSent,
    })
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'create failed'
    audit({
      userId: auth.user.id,
      actorUsername: auth.user.username,
      action: 'admin.user_create_failed',
      ip,
      userAgent,
      success: false,
      message: msg,
    })
    return NextResponse.json({ error: msg }, { status: 400 })
  }
}
