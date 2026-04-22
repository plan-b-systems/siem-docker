import { NextResponse } from 'next/server'
import { requireAdmin, getClientIp } from '@/lib/auth-require'
import { findUserById } from '@/lib/auth-users'
import { revokeAllSessionsForUser } from '@/lib/auth-session'
import { audit } from '@/lib/auth-audit'

export async function POST(req: Request, { params }: { params: { id: string } }) {
  const auth = await requireAdmin()
  if ('errorResponse' in auth) return auth.errorResponse
  const ip = getClientIp(req)
  const userAgent = req.headers.get('user-agent')

  const target = findUserById(params.id)
  if (!target) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  revokeAllSessionsForUser(target.id)
  audit({
    userId: auth.user.id,
    actorUsername: auth.user.username,
    action: 'admin.sessions_revoked',
    targetType: 'user',
    targetId: target.id,
    ip,
    userAgent,
    success: true,
  })
  return NextResponse.json({ success: true })
}
