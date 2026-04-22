import { NextResponse } from 'next/server'
import { requireAdmin, getClientIp } from '@/lib/auth-require'
import { findUserById, clearLockout } from '@/lib/auth-users'
import { audit } from '@/lib/auth-audit'

export async function POST(req: Request, { params }: { params: { id: string } }) {
  const auth = await requireAdmin()
  if ('errorResponse' in auth) return auth.errorResponse
  const ip = getClientIp(req)
  const userAgent = req.headers.get('user-agent')

  const target = findUserById(params.id)
  if (!target) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  clearLockout(target.id)
  audit({
    userId: auth.user.id,
    actorUsername: auth.user.username,
    action: 'admin.user_unlocked',
    targetType: 'user',
    targetId: target.id,
    ip,
    userAgent,
    success: true,
  })
  return NextResponse.json({ success: true })
}
