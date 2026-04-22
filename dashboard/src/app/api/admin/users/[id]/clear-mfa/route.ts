import { NextResponse } from 'next/server'
import { requireAdmin, getClientIp } from '@/lib/auth-require'
import { findUserById, updateUserFields } from '@/lib/auth-users'
import { audit } from '@/lib/auth-audit'

export async function POST(req: Request, { params }: { params: { id: string } }) {
  const auth = await requireAdmin()
  if ('errorResponse' in auth) return auth.errorResponse
  const ip = getClientIp(req)
  const userAgent = req.headers.get('user-agent')

  const target = findUserById(params.id)
  if (!target) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  updateUserFields(target.id, { mfa_enrolled: false, mfa_secret: null })
  audit({
    userId: auth.user.id,
    actorUsername: auth.user.username,
    action: 'admin.mfa_cleared',
    targetType: 'user',
    targetId: target.id,
    ip,
    userAgent,
    success: true,
  })
  return NextResponse.json({ success: true })
}
