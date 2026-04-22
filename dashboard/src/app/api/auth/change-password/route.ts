import { NextResponse } from 'next/server'
import { requireUser, getClientIp } from '@/lib/auth-require'
import { setPassword } from '@/lib/auth-users'
import { verifyPassword, validatePasswordPolicy, isPasswordReused } from '@/lib/auth-password'
import { audit } from '@/lib/auth-audit'
import { revokeAllSessionsForUser, issueSession, setSessionCookie } from '@/lib/auth-session'

export async function POST(req: Request) {
  const auth = await requireUser()
  if ('errorResponse' in auth) return auth.errorResponse
  const { user } = auth
  const ip = getClientIp(req)
  const userAgent = req.headers.get('user-agent')

  let body: { current_password?: string; new_password?: string }
  try {
    body = await req.json()
  } catch {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 })
  }
  const currentPassword = body.current_password || ''
  const newPassword = body.new_password || ''

  const policy = validatePasswordPolicy(newPassword, user.username)
  if (!policy.ok) return NextResponse.json({ error: policy.reason }, { status: 400 })

  const valid = await verifyPassword(currentPassword, user.password_hash)
  if (!valid) {
    audit({ userId: user.id, actorUsername: user.username, action: 'auth.change_password_failed', ip, userAgent, success: false, message: 'invalid_current' })
    return NextResponse.json({ error: 'Current password is incorrect' }, { status: 401 })
  }

  if (await isPasswordReused(user.id, newPassword)) {
    return NextResponse.json({ error: 'Password was used recently. Choose a different one.' }, { status: 400 })
  }

  await setPassword(user.id, newPassword)

  // Revoke all existing sessions except the current one — safer after password change.
  revokeAllSessionsForUser(user.id)
  const token = await issueSession(user.id, ip, userAgent)
  setSessionCookie(token)

  audit({ userId: user.id, actorUsername: user.username, action: 'auth.change_password', ip, userAgent, success: true })
  return NextResponse.json({ success: true })
}
