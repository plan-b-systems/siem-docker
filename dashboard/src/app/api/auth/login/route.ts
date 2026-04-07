import { NextResponse } from 'next/server'
import bcrypt from 'bcryptjs'
import { createSession, setSessionCookie } from '@/lib/auth'
import { config } from '@/lib/config'

export async function POST(req: Request) {
  try {
    const { password } = await req.json()

    if (!password) {
      return NextResponse.json({ error: 'Password required' }, { status: 400 })
    }

    const valid = await bcrypt.compare(password, config.dashboardPasswordHash)
    if (!valid) {
      return NextResponse.json({ error: 'Invalid password' }, { status: 401 })
    }

    const token = await createSession()
    setSessionCookie(token)

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('[login] Error:', error)
    return NextResponse.json({ error: 'Server error' }, { status: 500 })
  }
}
