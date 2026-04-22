import { NextResponse } from 'next/server'
import { requireAdmin, getClientIp } from '@/lib/auth-require'
import { findUserById, updateUserFields, deleteUser, countEnabledAdmins, toPublicUser } from '@/lib/auth-users'
import { revokeAllSessionsForUser } from '@/lib/auth-session'
import { audit } from '@/lib/auth-audit'

export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const auth = await requireAdmin()
  if ('errorResponse' in auth) return auth.errorResponse
  const user = findUserById(params.id)
  if (!user) return NextResponse.json({ error: 'Not found' }, { status: 404 })
  return NextResponse.json({ user: toPublicUser(user) })
}

export async function PATCH(req: Request, { params }: { params: { id: string } }) {
  const auth = await requireAdmin()
  if ('errorResponse' in auth) return auth.errorResponse
  const ip = getClientIp(req)
  const userAgent = req.headers.get('user-agent')

  const target = findUserById(params.id)
  if (!target) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  let body: Partial<{ email: string | null; full_name: string | null; role: 'admin' | 'user'; is_disabled: boolean }>
  try {
    body = await req.json()
  } catch {
    return NextResponse.json({ error: 'Invalid request' }, { status: 400 })
  }

  // Guard: prevent demoting / disabling the last admin.
  const wouldRemoveLastAdmin =
    target.role === 'admin' && !target.is_disabled &&
    ((body.role && body.role !== 'admin') || body.is_disabled === true) &&
    countEnabledAdmins() <= 1
  if (wouldRemoveLastAdmin) {
    return NextResponse.json({ error: 'Cannot remove the last enabled admin' }, { status: 400 })
  }

  const fields: Parameters<typeof updateUserFields>[1] = {}
  if ('email' in body) fields.email = body.email ?? null
  if ('full_name' in body) fields.full_name = body.full_name ?? null
  if (body.role === 'admin' || body.role === 'user') fields.role = body.role
  if (typeof body.is_disabled === 'boolean') fields.is_disabled = body.is_disabled

  updateUserFields(target.id, fields)

  if (body.is_disabled === true) revokeAllSessionsForUser(target.id)

  audit({
    userId: auth.user.id,
    actorUsername: auth.user.username,
    action: 'admin.user_updated',
    targetType: 'user',
    targetId: target.id,
    ip,
    userAgent,
    success: true,
    message: JSON.stringify(fields),
  })

  const updated = findUserById(target.id)!
  return NextResponse.json({ user: toPublicUser(updated) })
}

export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  const auth = await requireAdmin()
  if ('errorResponse' in auth) return auth.errorResponse
  const ip = getClientIp(req)
  const userAgent = req.headers.get('user-agent')

  const target = findUserById(params.id)
  if (!target) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  if (target.id === auth.user.id) {
    return NextResponse.json({ error: 'Cannot delete your own account' }, { status: 400 })
  }
  if (target.role === 'admin' && !target.is_disabled && countEnabledAdmins() <= 1) {
    return NextResponse.json({ error: 'Cannot delete the last enabled admin' }, { status: 400 })
  }

  revokeAllSessionsForUser(target.id)
  deleteUser(target.id)
  audit({
    userId: auth.user.id,
    actorUsername: auth.user.username,
    action: 'admin.user_deleted',
    targetType: 'user',
    targetId: target.id,
    ip,
    userAgent,
    success: true,
    message: `deleted ${target.username}`,
  })
  return NextResponse.json({ success: true })
}
