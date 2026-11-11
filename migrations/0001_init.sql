-- Users / instances: each user has isolated rules + plugin + tokens
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT,
  role TEXT NOT NULL DEFAULT 'user', -- 'owner' | 'user'
  admin_token TEXT NOT NULL UNIQUE,  -- legacy/admin URL token (compat)
  sub_token TEXT NOT NULL UNIQUE,
  ipv6_host_domain TEXT DEFAULT '',
  rules_text TEXT NOT NULL DEFAULT '',
  plugin_text TEXT,
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_users_admin_token ON users(admin_token);
CREATE INDEX IF NOT EXISTS idx_users_sub_token ON users(sub_token);

-- Sessions for username/password login
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
