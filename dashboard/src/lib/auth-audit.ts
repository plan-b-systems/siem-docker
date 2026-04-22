import { getDb } from './auth-db'

export type AuditEntry = {
  userId?: string | null
  actorUsername?: string | null
  action: string
  targetType?: string | null
  targetId?: string | null
  ip?: string | null
  userAgent?: string | null
  success: boolean
  message?: string | null
}

export function audit(entry: AuditEntry) {
  try {
    const db = getDb()
    db.prepare(`
      INSERT INTO audit_log (user_id, actor_username, action, target_type, target_id, ip, user_agent, success, message, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      entry.userId ?? null,
      entry.actorUsername ?? null,
      entry.action,
      entry.targetType ?? null,
      entry.targetId ?? null,
      entry.ip ?? null,
      entry.userAgent ?? null,
      entry.success ? 1 : 0,
      entry.message ?? null,
      Date.now()
    )
  } catch (err) {
    console.error('[audit] Failed to write audit entry:', err)
  }
}

export function listAudit(opts: { limit?: number; offset?: number; userId?: string; action?: string } = {}) {
  const db = getDb()
  const limit = Math.min(Math.max(opts.limit ?? 100, 1), 1000)
  const offset = Math.max(opts.offset ?? 0, 0)

  const filters: string[] = []
  const params: (string | number)[] = []
  if (opts.userId) { filters.push('user_id = ?'); params.push(opts.userId) }
  if (opts.action) { filters.push('action = ?'); params.push(opts.action) }
  const where = filters.length ? `WHERE ${filters.join(' AND ')}` : ''

  const rows = db.prepare(`
    SELECT id, user_id, actor_username, action, target_type, target_id, ip, user_agent, success, message, created_at
    FROM audit_log
    ${where}
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, limit, offset)

  return rows
}
