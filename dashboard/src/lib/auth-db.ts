import Database from 'better-sqlite3'
import fs from 'fs'
import path from 'path'

const DB_PATH = process.env.AUTH_DB_PATH || '/auth-data/users.db'

type DbHandle = ReturnType<typeof Database>

declare global {
  // Cache DB connection across hot-reloads in dev so we don't exhaust fds.
  // eslint-disable-next-line no-var
  var __planbAuthDb: DbHandle | undefined
}

function openDb(): DbHandle {
  const dir = path.dirname(DB_PATH)
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 })

  const db = new Database(DB_PATH)
  db.pragma('journal_mode = WAL')
  db.pragma('foreign_keys = ON')
  db.pragma('synchronous = NORMAL')
  return db
}

function runMigrations(db: DbHandle) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_version (
      version INTEGER PRIMARY KEY
    );
  `)
  const row = db.prepare('SELECT COALESCE(MAX(version), 0) AS v FROM schema_version').get() as { v: number }
  const current = row.v

  const migrations: { version: number; sql: string }[] = [
    {
      version: 1,
      sql: `
        CREATE TABLE users (
          id TEXT PRIMARY KEY,
          username TEXT NOT NULL UNIQUE COLLATE NOCASE,
          email TEXT,
          full_name TEXT,
          password_hash TEXT NOT NULL,
          must_change_password INTEGER NOT NULL DEFAULT 0,
          mfa_enrolled INTEGER NOT NULL DEFAULT 0,
          mfa_secret TEXT,
          role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin','user')),
          is_disabled INTEGER NOT NULL DEFAULT 0,
          failed_attempts INTEGER NOT NULL DEFAULT 0,
          locked_until INTEGER,
          last_login_at INTEGER,
          last_login_ip TEXT,
          created_at INTEGER NOT NULL,
          updated_at INTEGER NOT NULL
        );
        CREATE INDEX idx_users_username ON users(username);

        CREATE TABLE password_history (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          password_hash TEXT NOT NULL,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX idx_password_history_user ON password_history(user_id, created_at DESC);

        CREATE TABLE password_reset_tokens (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          token_hash TEXT NOT NULL,
          expires_at INTEGER NOT NULL,
          used_at INTEGER,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX idx_reset_tokens_hash ON password_reset_tokens(token_hash);
        CREATE INDEX idx_reset_tokens_user ON password_reset_tokens(user_id, created_at DESC);

        CREATE TABLE sessions (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          issued_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          idle_expires_at INTEGER NOT NULL,
          ip TEXT,
          user_agent TEXT,
          revoked_at INTEGER
        );
        CREATE INDEX idx_sessions_user ON sessions(user_id);
        CREATE INDEX idx_sessions_expires ON sessions(expires_at);

        CREATE TABLE audit_log (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id TEXT,
          actor_username TEXT,
          action TEXT NOT NULL,
          target_type TEXT,
          target_id TEXT,
          ip TEXT,
          user_agent TEXT,
          success INTEGER NOT NULL,
          message TEXT,
          created_at INTEGER NOT NULL
        );
        CREATE INDEX idx_audit_created ON audit_log(created_at DESC);
        CREATE INDEX idx_audit_user ON audit_log(user_id, created_at DESC);
        CREATE INDEX idx_audit_action ON audit_log(action, created_at DESC);
      `,
    },
  ]

  const apply = db.transaction((mig: { version: number; sql: string }) => {
    db.exec(mig.sql)
    db.prepare('INSERT INTO schema_version (version) VALUES (?)').run(mig.version)
  })

  for (const mig of migrations) {
    if (mig.version > current) apply(mig)
  }
}

export function getDb(): DbHandle {
  if (global.__planbAuthDb) return global.__planbAuthDb
  const db = openDb()
  runMigrations(db)
  global.__planbAuthDb = db
  return db
}

export function closeDb() {
  if (global.__planbAuthDb) {
    global.__planbAuthDb.close()
    global.__planbAuthDb = undefined
  }
}

export type UserRow = {
  id: string
  username: string
  email: string | null
  full_name: string | null
  password_hash: string
  must_change_password: number
  mfa_enrolled: number
  mfa_secret: string | null
  role: 'admin' | 'user'
  is_disabled: number
  failed_attempts: number
  locked_until: number | null
  last_login_at: number | null
  last_login_ip: string | null
  created_at: number
  updated_at: number
}

export type SessionRow = {
  id: string
  user_id: string
  issued_at: number
  expires_at: number
  idle_expires_at: number
  ip: string | null
  user_agent: string | null
  revoked_at: number | null
}

export type AuditRow = {
  id: number
  user_id: string | null
  actor_username: string | null
  action: string
  target_type: string | null
  target_id: string | null
  ip: string | null
  user_agent: string | null
  success: number
  message: string | null
  created_at: number
}
