import { NextResponse } from 'next/server'
import { UserRow } from './auth-db'
import { getSessionCookie, validateSession } from './auth-session'
import { findUserById } from './auth-users'

export async function requireUser(): Promise<
  { user: UserRow; jti: string } | { errorResponse: NextResponse }
> {
  const token = getSessionCookie()
  if (!token) return { errorResponse: NextResponse.json({ error: 'Not authenticated' }, { status: 401 }) }
  const session = await validateSession(token)
  if (!session) return { errorResponse: NextResponse.json({ error: 'Invalid session' }, { status: 401 }) }
  const user = findUserById(session.userId)
  if (!user || user.is_disabled) {
    return { errorResponse: NextResponse.json({ error: 'User unavailable' }, { status: 401 }) }
  }
  return { user, jti: session.jti }
}

export async function requireAdmin(): Promise<
  { user: UserRow; jti: string } | { errorResponse: NextResponse }
> {
  const result = await requireUser()
  if ('errorResponse' in result) return result
  if (result.user.role !== 'admin') {
    return { errorResponse: NextResponse.json({ error: 'Admin role required' }, { status: 403 }) }
  }
  return result
}

export function getClientIp(request: Request): string | null {
  const xff = request.headers.get('x-forwarded-for')
  if (xff) return xff.split(',')[0].trim()
  return request.headers.get('x-real-ip')
}
