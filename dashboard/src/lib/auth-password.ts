import bcrypt from 'bcryptjs'
import { getDb } from './auth-db'

export const PASSWORD_MIN_LENGTH = 12
export const PASSWORD_HISTORY_SIZE = 5
export const BCRYPT_ROUNDS = 12

export type PasswordPolicyResult = { ok: true } | { ok: false; reason: string }

export function validatePasswordPolicy(password: string, username?: string): PasswordPolicyResult {
  if (!password || password.length < PASSWORD_MIN_LENGTH) {
    return { ok: false, reason: `Password must be at least ${PASSWORD_MIN_LENGTH} characters` }
  }
  if (!/[a-z]/.test(password)) return { ok: false, reason: 'Password must contain a lowercase letter' }
  if (!/[A-Z]/.test(password)) return { ok: false, reason: 'Password must contain an uppercase letter' }
  if (!/[0-9]/.test(password)) return { ok: false, reason: 'Password must contain a digit' }
  if (username && password.toLowerCase().includes(username.toLowerCase())) {
    return { ok: false, reason: 'Password cannot contain the username' }
  }
  return { ok: true }
}

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, BCRYPT_ROUNDS)
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  try {
    return await bcrypt.compare(password, hash)
  } catch {
    return false
  }
}

export async function isPasswordReused(userId: string, password: string): Promise<boolean> {
  const db = getDb()
  const rows = db
    .prepare('SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?')
    .all(userId, PASSWORD_HISTORY_SIZE) as { password_hash: string }[]
  for (const row of rows) {
    if (await verifyPassword(password, row.password_hash)) return true
  }
  return false
}

export function recordPasswordHistory(userId: string, passwordHash: string) {
  const db = getDb()
  const now = Date.now()
  db.prepare('INSERT INTO password_history (user_id, password_hash, created_at) VALUES (?, ?, ?)').run(
    userId,
    passwordHash,
    now
  )
  // Prune beyond the last N
  db.prepare(`
    DELETE FROM password_history
    WHERE user_id = ?
      AND id NOT IN (
        SELECT id FROM password_history WHERE user_id = ? ORDER BY created_at DESC LIMIT ?
      )
  `).run(userId, userId, PASSWORD_HISTORY_SIZE)
}
