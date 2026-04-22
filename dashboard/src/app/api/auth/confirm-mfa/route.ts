import { NextResponse } from 'next/server'
import { requireUser, getClientIp } from '@/lib/auth-require'
import { verifyTotp } from '@/lib/auth-totp'
import { updateUserFields } from '@/lib/auth-users'
import { audit } from '@/lib/auth-audit'

export async function POST(req: Request) {
  const auth = await requireUser()
  if ('errorResponse' in auth) return auth.errorResponse
  const { user } = auth
  const ip = getClientIp(req)
  const userAgent = req.headers.get('user-agent')

  if (!user.mfa_secret) {
    return NextResponse.json({ error: 'No pending MFA secret. Call /api/auth/enroll-mfa first.' }, { status: 400 })
  }

  let body: { totp_code?: string }
  try {
    body = await req.json()
  } catch {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 })
  }
  const code = body.totp_code || ''
  if (!verifyTotp(code, user.mfa_secret)) {
    audit({ userId: user.id, actorUsername: user.username, action: 'auth.mfa_enroll_failed', ip, userAgent, success: false, message: 'bad_code' })
    return NextResponse.json({ error: 'Invalid code' }, { status: 400 })
  }

  updateUserFields(user.id, { mfa_enrolled: true })
  audit({ userId: user.id, actorUsername: user.username, action: 'auth.mfa_enrolled', ip, userAgent, success: true })
  return NextResponse.json({ success: true })
}
