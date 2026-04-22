import { NextResponse } from 'next/server'
import { getSessionCookie, validateSession, revokeSession, clearSessionCookie } from '@/lib/auth-session'
import { audit } from '@/lib/auth-audit'
import { findUserById } from '@/lib/auth-users'
import { getClientIp } from '@/lib/auth-require'

export async function POST(req: Request) {
  const ip = getClientIp(req)
  const userAgent = req.headers.get('user-agent')
  const token = getSessionCookie()
  if (token) {
    const session = await validateSession(token, { touch: false })
    if (session) {
      const user = findUserById(session.userId)
      revokeSession(session.jti)
      audit({
        userId: session.userId,
        actorUsername: user?.username ?? null,
        action: 'auth.logout',
        ip,
        userAgent,
        success: true,
      })
    }
  }
  clearSessionCookie()
  return NextResponse.json({ success: true })
}

export async function DELETE(req: Request) {
  return POST(req)
}
