import { NextResponse } from 'next/server'
import { jwtVerify } from 'jose'
import { findUserById, recordSuccessfulLogin, recordFailedLogin, toPublicUser } from '@/lib/auth-users'
import { issueSession, setSessionCookie } from '@/lib/auth-session'
import { verifyTotp } from '@/lib/auth-totp'
import { audit } from '@/lib/auth-audit'
import { getClientIp } from '@/lib/auth-require'

function getSecret() {
  return new TextEncoder().encode(process.env.JWT_SECRET || 'dev-secret-change-in-production')
}

export async function POST(req: Request) {
  const ip = getClientIp(req)
  const userAgent = req.headers.get('user-agent')

  let body: { temp_token?: string; totp_code?: string }
  try {
    body = await req.json()
  } catch {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 })
  }
  const tempToken = body.temp_token
  const code = body.totp_code || ''
  if (!tempToken || !code) {
    return NextResponse.json({ error: 'Missing token or code' }, { status: 400 })
  }

  let userId: string
  try {
    const { payload } = await jwtVerify(tempToken, getSecret())
    if (payload.stage !== 'mfa_pending' || !payload.sub) {
      return NextResponse.json({ error: 'Invalid pending token' }, { status: 401 })
    }
    userId = payload.sub as string
  } catch {
    return NextResponse.json({ error: 'Pending token expired. Start over.' }, { status: 401 })
  }

  const user = findUserById(userId)
  if (!user || user.is_disabled) {
    return NextResponse.json({ error: 'User unavailable' }, { status: 401 })
  }
  if (!user.mfa_enrolled || !user.mfa_secret) {
    return NextResponse.json({ error: 'MFA not enrolled' }, { status: 400 })
  }

  const valid = verifyTotp(code, user.mfa_secret)
  if (!valid) {
    const lockInfo = recordFailedLogin(user.id)
    audit({
      userId: user.id,
      actorUsername: user.username,
      action: 'auth.mfa_failed',
      ip,
      userAgent,
      success: false,
      message: lockInfo.locked ? 'Locked after MFA failures' : `Failed MFA attempt ${lockInfo.failedAttempts}`,
    })
    if (lockInfo.locked) {
      return NextResponse.json({ error: 'Account locked after too many failed MFA attempts.' }, { status: 401 })
    }
    return NextResponse.json({ error: 'Invalid MFA code' }, { status: 401 })
  }

  recordSuccessfulLogin(user.id, ip)
  const token = await issueSession(user.id, ip, userAgent)
  setSessionCookie(token)
  audit({
    userId: user.id,
    actorUsername: user.username,
    action: 'auth.login_success',
    ip,
    userAgent,
    success: true,
    message: 'mfa_verified',
  })
  return NextResponse.json({
    stage: 'authenticated',
    user: toPublicUser(user),
    must_change_password: !!user.must_change_password,
    mfa_enrolled: true,
  })
}
