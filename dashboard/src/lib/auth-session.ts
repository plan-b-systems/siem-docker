import crypto from 'crypto'
import { SignJWT, jwtVerify } from 'jose'
import { cookies } from 'next/headers'
import { getDb, SessionRow } from './auth-db'

const JWT_COOKIE = 'plan_b_session'
const SESSION_ABSOLUTE_MS = 24 * 60 * 60 * 1000
const SESSION_IDLE_MS = 60 * 60 * 1000

function getSecret() {
  return new TextEncoder().encode(process.env.JWT_SECRET || 'dev-secret-change-in-production')
}

export async function issueSession(userId: string, ip: string | null, userAgent: string | null): Promise<string> {
  const jti = crypto.randomUUID()
  const now = Date.now()
  const absExp = now + SESSION_ABSOLUTE_MS
  const idleExp = now + SESSION_IDLE_MS

  const db = getDb()
  db.prepare(`
    INSERT INTO sessions (id, user_id, issued_at, expires_at, idle_expires_at, ip, user_agent)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(jti, userId, now, absExp, idleExp, ip, userAgent)

  const token = await new SignJWT({ sub: userId, jti })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt(Math.floor(now / 1000))
    .setExpirationTime(Math.floor(absExp / 1000))
    .sign(getSecret())

  return token
}

export function setSessionCookie(token: string) {
  // secure=false by default because many on-prem installs run over plain HTTP
  // initially. Opt in via COOKIE_SECURE=1 once TLS is fronting the container.
  const secure = process.env.COOKIE_SECURE === '1'
  cookies().set(JWT_COOKIE, token, {
    httpOnly: true,
    secure,
    sameSite: 'lax',
    maxAge: SESSION_ABSOLUTE_MS / 1000,
    path: '/',
  })
}

export function getSessionCookie(): string | undefined {
  return cookies().get(JWT_COOKIE)?.value
}

export function clearSessionCookie() {
  cookies().delete(JWT_COOKIE)
}

export async function validateSession(token: string, opts: { touch?: boolean } = {}): Promise<{ userId: string; jti: string } | null> {
  try {
    const { payload } = await jwtVerify(token, getSecret())
    const jti = payload.jti as string | undefined
    const userId = payload.sub as string | undefined
    if (!jti || !userId) return null
    const db = getDb()
    const row = db.prepare('SELECT * FROM sessions WHERE id = ?').get(jti) as SessionRow | undefined
    if (!row) return null
    if (row.revoked_at) return null
    const now = Date.now()
    if (row.expires_at <= now) return null
    if (row.idle_expires_at <= now) return null
    if (opts.touch !== false) {
      db.prepare('UPDATE sessions SET idle_expires_at = ? WHERE id = ?').run(now + SESSION_IDLE_MS, jti)
    }
    return { userId, jti }
  } catch {
    return null
  }
}

export function revokeSession(jti: string) {
  const db = getDb()
  db.prepare('UPDATE sessions SET revoked_at = ? WHERE id = ?').run(Date.now(), jti)
}

export function revokeAllSessionsForUser(userId: string) {
  const db = getDb()
  db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL')
    .run(Date.now(), userId)
}

export function listActiveSessions(userId: string) {
  const db = getDb()
  const now = Date.now()
  return db.prepare(`
    SELECT id, issued_at, expires_at, idle_expires_at, ip, user_agent
    FROM sessions
    WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? AND idle_expires_at > ?
    ORDER BY issued_at DESC
  `).all(userId, now, now)
}
