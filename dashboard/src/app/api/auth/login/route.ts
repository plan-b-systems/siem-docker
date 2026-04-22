import { NextResponse } from 'next/server'
import { SignJWT } from 'jose'
import {
  authenticate,
  recordFailedLogin,
  recordSuccessfulLogin,
  toPublicUser,
} from '@/lib/auth-users'
import { issueSession, setSessionCookie } from '@/lib/auth-session'
import { ensureBootstrapped } from '@/lib/auth-bootstrap'
import { audit } from '@/lib/auth-audit'
import { getClientIp } from '@/lib/auth-require'

const MFA_PENDING_TTL_SECONDS = 5 * 60

function getSecret() {
  return new TextEncoder().encode(process.env.JWT_SECRET || 'dev-secret-change-in-production')
}

async function issueMfaPendingToken(userId: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  return new SignJWT({ sub: userId, stage: 'mfa_pending' })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt(now)
    .setExpirationTime(now + MFA_PENDING_TTL_SECONDS)
    .sign(getSecret())
}

export async function POST(req: Request) {
  await ensureBootstrapped()
  const ip = getClientIp(req)
  const userAgent = req.headers.get('user-agent')

  let body: { username?: string; password?: string }
  try {
    body = await req.json()
  } catch {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 })
  }
  const username = (body.username || '').trim()
  const password = body.password || ''
  if (!username || !password) {
    return NextResponse.json({ error: 'Username and password required' }, { status: 400 })
  }

  const result = await authenticate(username, password)
  if (!result.ok) {
    if (result.user && result.reason === 'invalid') {
      const lockInfo = recordFailedLogin(result.user.id)
      audit({
        userId: result.user.id,
        actorUsername: result.user.username,
        action: 'auth.login_failed',
        ip,
        userAgent,
        success: false,
        message: lockInfo.locked ? `Account locked after ${lockInfo.failedAttempts} attempts` : `Failed attempt ${lockInfo.failedAttempts}`,
      })
      if (lockInfo.locked) {
        return NextResponse.json({ error: 'Account locked after too many failed attempts. Try again in 15 minutes.' }, { status: 401 })
      }
    } else {
      audit({
        actorUsername: username,
        action: 'auth.login_failed',
        ip,
        userAgent,
        success: false,
        message: result.reason,
      })
    }
    if (result.reason === 'locked') {
      return NextResponse.json({ error: 'Account locked. Try again later.' }, { status: 401 })
    }
    if (result.reason === 'disabled') {
      return NextResponse.json({ error: 'Account disabled.' }, { status: 401 })
    }
    return NextResponse.json({ error: 'Invalid username or password' }, { status: 401 })
  }

  const user = result.user

  // Requires a second-factor prompt
  if (user.mfa_enrolled) {
    const tempToken = await issueMfaPendingToken(user.id)
    audit({
      userId: user.id,
      actorUsername: user.username,
      action: 'auth.password_ok_awaiting_mfa',
      ip,
      userAgent,
      success: true,
    })
    return NextResponse.json({
      stage: 'mfa_required',
      temp_token: tempToken,
    })
  }

  // No MFA yet — issue the session and flag forced enrolment via the response.
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
    message: 'mfa_not_enrolled',
  })
  return NextResponse.json({
    stage: 'authenticated',
    user: toPublicUser(user),
    must_change_password: !!user.must_change_password,
    mfa_enrolled: false,
  })
}
