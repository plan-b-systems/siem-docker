import { NextResponse } from 'next/server'
import { requireAdmin } from '@/lib/auth-require'
import { listAudit } from '@/lib/auth-audit'

export async function GET(req: Request) {
  const auth = await requireAdmin()
  if ('errorResponse' in auth) return auth.errorResponse

  const url = new URL(req.url)
  const limit = parseInt(url.searchParams.get('limit') || '200', 10)
  const offset = parseInt(url.searchParams.get('offset') || '0', 10)
  const userId = url.searchParams.get('user_id') || undefined
  const action = url.searchParams.get('action') || undefined

  const entries = listAudit({ limit, offset, userId, action })
  return NextResponse.json({ entries })
}
