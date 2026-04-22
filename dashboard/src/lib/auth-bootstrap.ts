import crypto from 'crypto'
import { getDb } from './auth-db'
import { audit } from './auth-audit'

const ADMIN_USERNAME = 'admin'

let bootstrapPromise: Promise<void> | null = null

export function ensureBootstrapped(): Promise<void> {
  if (!bootstrapPromise) bootstrapPromise = bootstrapAdminIfNeeded()
  return bootstrapPromise
}

/**
 * On first boot, seed a single 'admin' user using the existing
 * DASHBOARD_PASSWORD_HASH environment variable. The admin is forced to
 * change their password and enrol MFA on first login.
 *
 * Safe to call on every boot — becomes a no-op once the row exists.
 */
export async function bootstrapAdminIfNeeded(): Promise<void> {
  const db = getDb()
  const row = db.prepare('SELECT COUNT(*) AS n FROM users').get() as { n: number }
  if (row.n > 0) return

  const legacyHash = process.env.DASHBOARD_PASSWORD_HASH
  if (!legacyHash) {
    // No legacy hash either — leave empty. Operator must create first user via CLI.
    console.warn('[auth-bootstrap] No users exist and DASHBOARD_PASSWORD_HASH is unset; run reset-admin-cli to create the first admin.')
    return
  }

  // Seed the admin user by direct insert (bypassing createUser so we keep the existing hash unchanged).
  const id = crypto.randomUUID()
  const now = Date.now()
  db.prepare(`
    INSERT INTO users (id, username, email, full_name, password_hash, must_change_password, mfa_enrolled, role, created_at, updated_at)
    VALUES (?, 'admin', NULL, 'Administrator', ?, 1, 0, 'admin', ?, ?)
  `).run(id, legacyHash, now, now)

  db.prepare('INSERT INTO password_history (user_id, password_hash, created_at) VALUES (?, ?, ?)')
    .run(id, legacyHash, now)

  audit({
    action: 'bootstrap.admin_seeded',
    actorUsername: 'system',
    targetType: 'user',
    targetId: id,
    success: true,
    message: 'Initial admin user created from DASHBOARD_PASSWORD_HASH; must_change_password=1',
  })
  console.log('[auth-bootstrap] Seeded initial admin user; must change password and enrol MFA on first login.')
}

/**
 * Helper used by the emergency CLI (reset-admin-cli): force-resets the admin's
 * password to a new value, clears lockout, clears MFA (operator must re-enrol).
 */
export async function emergencyResetAdmin(newPassword: string): Promise<void> {
  const { createUser, findUserByUsername, setPassword, updateUserFields } = await import('./auth-users')
  const existing = findUserByUsername(ADMIN_USERNAME)
  if (!existing) {
    await createUser({ username: ADMIN_USERNAME, password: newPassword, role: 'admin', must_change_password: true, full_name: 'Administrator' })
    return
  }
  await setPassword(existing.id, newPassword)
  updateUserFields(existing.id, {
    must_change_password: true,
    mfa_enrolled: false,
    mfa_secret: null,
    is_disabled: false,
    locked_until: null,
    failed_attempts: 0,
  })
  audit({
    action: 'cli.emergency_reset_admin',
    actorUsername: 'cli',
    targetType: 'user',
    targetId: existing.id,
    success: true,
    message: 'Admin password force-reset via CLI; MFA cleared',
  })
}
