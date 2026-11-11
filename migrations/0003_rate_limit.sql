-- 0003: login brute-force protection counters (per-IP + per-account).
-- key is "ip:<CF-Connecting-IP>" or "user:<username>".
CREATE TABLE IF NOT EXISTS login_attempts (
  key TEXT PRIMARY KEY,
  failures INTEGER NOT NULL DEFAULT 0,
  last_attempt INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0
);
