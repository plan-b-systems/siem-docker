import { NextResponse } from 'next/server'
import { requireUser } from '@/lib/auth-require'
import { toPublicUser } from '@/lib/auth-users'

export async function GET() {
  const auth = await requireUser()
  if ('errorResponse' in auth) return auth.errorResponse
  return NextResponse.json({ user: toPublicUser(auth.user) })
}
