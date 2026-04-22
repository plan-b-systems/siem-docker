import crypto from 'crypto'
import { getDb, UserRow } from './auth-db'
import { hashPassword, verifyPassword, recordPasswordHistory } from './auth-password'

export const LOCKOUT_THRESHOLD = 5
export const LOCKOUT_WINDOW_MS = 15 * 60 * 1000

export type PublicUser = {
  id: string
  username: string
  email: string | null
  full_name: string | null
  role: 'admin' | 'user'
  must_change_password: boolean
  mfa_enrolled: boolean
  is_disabled: boolean
  is_locked: boolean
  last_login_at: number | null
  last_login_ip: string | null
  created_at: number
}

function toPublic(u: UserRow): PublicUser {
  const now = Date.now()
  return {
    id: u.id,
    username: u.username,
    email: u.email,
    full_name: u.full_name,
    role: u.role,
    must_change_password: !!u.must_change_password,
    mfa_enrolled: !!u.mfa_enrolled,
    is_disabled: !!u.is_disabled,
    is_locked: !!(u.locked_until && u.locked_until > now),
    last_login_at: u.last_login_at,
    last_login_ip: u.last_login_ip,
    created_at: u.created_at,
  }
}

export function findUserByUsername(username: string): UserRow | null {
  const db = getDb()
  const row = db.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE').get(username) as UserRow | undefined
  return row ?? null
}

export function findUserById(id: string): UserRow | null {
  const db = getDb()
  const row = db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined
  return row ?? null
}

export function listUsers(): PublicUser[] {
  const db = getDb()
  const rows = db.prepare('SELECT * FROM users ORDER BY created_at ASC').all() as UserRow[]
  return rows.map(toPublic)
}

export function toPublicUser(u: UserRow): PublicUser {
  return toPublic(u)
}

export async function createUser(input: {
  username: string
  password: string
  email?: string
  full_name?: string
  role?: 'admin' | 'user'
  must_change_password?: boolean
}): Promise<PublicUser> {
  const db = getDb()
  const existing = findUserByUsername(input.username)
  if (existing) throw new Error('Username already exists')
  const id = crypto.randomUUID()
  const now = Date.now()
  const hash = await hashPassword(input.password)
  db.prepare(`
    INSERT INTO users (id, username, email, full_name, password_hash, must_change_password, mfa_enrolled, role, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
  `).run(
    id,
    input.username,
    input.email ?? null,
    input.full_name ?? null,
    hash,
    input.must_change_password ? 1 : 0,
    input.role ?? 'user',
    now,
    now
  )
  recordPasswordHistory(id, hash)
  const row = findUserById(id)!
  return toPublic(row)
}

export function updateUserFields(id: string, fields: Partial<{
  email: string | null
  full_name: string | null
  role: 'admin' | 'user'
  is_disabled: boolean
  must_change_password: boolean
  mfa_enrolled: boolean
  mfa_secret: string | null
  locked_until: number | null
  failed_attempts: number
}>) {
  const db = getDb()
  const setClauses: string[] = []
  const params: (string | number | null)[] = []
  for (const [k, v] of Object.entries(fields)) {
    setClauses.push(`${k} = ?`)
    if (typeof v === 'boolean') params.push(v ? 1 : 0)
    else params.push(v as string | number | null)
  }
  if (!setClauses.length) return
  setClauses.push('updated_at = ?')
  params.push(Date.now(), id)
  db.prepare(`UPDATE users SET ${setClauses.join(', ')} WHERE id = ?`).run(...params)
}

export async function setPassword(userId: string, newPassword: string) {
  const hash = await hashPassword(newPassword)
  const db = getDb()
  db.prepare('UPDATE users SET password_hash = ?, must_change_password = 0, updated_at = ? WHERE id = ?')
    .run(hash, Date.now(), userId)
  recordPasswordHistory(userId, hash)
}

export function deleteUser(id: string) {
  const db = getDb()
  db.prepare('DELETE FROM users WHERE id = ?').run(id)
}

/** Count admins currently enabled. Used to prevent self-lockout. */
export function countEnabledAdmins(): number {
  const db = getDb()
  const row = db.prepare(`SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND is_disabled = 0`).get() as { n: number }
  return row.n
}

export function recordSuccessfulLogin(userId: string, ip: string | null) {
  const db = getDb()
  db.prepare(`
    UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = ?, last_login_ip = ?, updated_at = ? WHERE id = ?
  `).run(Date.now(), ip, Date.now(), userId)
}

export function recordFailedLogin(userId: string): { locked: boolean; failedAttempts: number } {
  const db = getDb()
  const user = findUserById(userId)
  if (!user) return { locked: false, failedAttempts: 0 }
  const attempts = (user.failed_attempts || 0) + 1
  const shouldLock = attempts >= LOCKOUT_THRESHOLD
  const lockedUntil = shouldLock ? Date.now() + LOCKOUT_WINDOW_MS : user.locked_until
  db.prepare('UPDATE users SET failed_attempts = ?, locked_until = ?, updated_at = ? WHERE id = ?')
    .run(attempts, lockedUntil, Date.now(), userId)
  return { locked: shouldLock, failedAttempts: attempts }
}

export function clearLockout(userId: string) {
  const db = getDb()
  db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?')
    .run(Date.now(), userId)
}

export function isUserLocked(user: UserRow): boolean {
  return !!(user.locked_until && user.locked_until > Date.now())
}

/**
 * Verify a username+password combination. Handles lockout bookkeeping.
 * Returns the matched UserRow on success; null (with a reason) on failure.
 */
export async function authenticate(username: string, password: string): Promise<
  { ok: true; user: UserRow } |
  { ok: false; reason: 'invalid' | 'disabled' | 'locked'; user?: UserRow }
> {
  const user = findUserByUsername(username)
  if (!user) return { ok: false, reason: 'invalid' }
  if (user.is_disabled) return { ok: false, reason: 'disabled', user }
  if (isUserLocked(user)) return { ok: false, reason: 'locked', user }
  const valid = await verifyPassword(password, user.password_hash)
  if (!valid) return { ok: false, reason: 'invalid', user }
  return { ok: true, user }
}
