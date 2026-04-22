#!/usr/bin/env node
/**
 * Emergency admin-reset CLI.
 *
 * Usage (from the host, via docker exec):
 *   docker exec -it plan-b-dashboard node scripts/reset-admin.js <new-password>
 *
 * If no password is given, a random one is generated and printed.
 *
 * Effect:
 *  - If an 'admin' user exists: password is replaced, MFA cleared, disabled/locked flags cleared,
 *    must_change_password set to 1.
 *  - Otherwise: a new 'admin' user is created with the given/generated password,
 *    must_change_password = 1 and role = 'admin'.
 *
 * The reset is logged to audit_log with action 'cli.emergency_reset_admin'.
 */

const crypto = require('crypto')
const Database = require('better-sqlite3')
const bcrypt = require('bcryptjs')

const AUTH_DB_PATH = process.env.AUTH_DB_PATH || '/auth-data/users.db'

function generatePassword() {
  return crypto.randomBytes(12).toString('base64').replace(/[+/=]/g, '') + 'Aa1'
}

function main() {
  let newPassword = process.argv[2]
  let generated = false
  if (!newPassword) {
    newPassword = generatePassword()
    generated = true
  }
  if (newPassword.length < 12) {
    console.error('Password must be at least 12 characters.')
    process.exit(2)
  }

  const db = new Database(AUTH_DB_PATH)
  db.pragma('foreign_keys = ON')

  const hash = bcrypt.hashSync(newPassword, 12)
  const now = Date.now()

  const existing = db.prepare("SELECT id FROM users WHERE username = 'admin' COLLATE NOCASE").get()

  let userId
  if (existing) {
    userId = existing.id
    db.prepare(`
      UPDATE users SET
        password_hash = ?,
        must_change_password = 1,
        mfa_enrolled = 0,
        mfa_secret = NULL,
        is_disabled = 0,
        failed_attempts = 0,
        locked_until = NULL,
        updated_at = ?
      WHERE id = ?
    `).run(hash, now, userId)
    console.log('Reset existing admin user.')
  } else {
    userId = crypto.randomUUID()
    db.prepare(`
      INSERT INTO users (id, username, full_name, password_hash, must_change_password, mfa_enrolled, role, created_at, updated_at)
      VALUES (?, 'admin', 'Administrator', ?, 1, 0, 'admin', ?, ?)
    `).run(userId, hash, now, now)
    console.log('Created new admin user.')
  }

  // Record in password history so policy does not treat this as reused against itself.
  db.prepare('INSERT INTO password_history (user_id, password_hash, created_at) VALUES (?, ?, ?)').run(userId, hash, now)

  // Revoke any existing sessions for the admin.
  db.prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').run(now, userId)

  // Audit.
  db.prepare(`
    INSERT INTO audit_log (user_id, actor_username, action, target_type, target_id, success, message, created_at)
    VALUES (NULL, 'cli', 'cli.emergency_reset_admin', 'user', ?, 1, 'Admin reset via emergency CLI — must change password and enrol MFA', ?)
  `).run(userId, now)

  console.log('Username: admin')
  console.log('Password: ' + newPassword + (generated ? '  (generated — save this)' : ''))
  console.log('On first login the user must change the password and enrol MFA.')
}

main()
