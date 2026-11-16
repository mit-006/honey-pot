-- Honeypot Atlas : data tier (PostgreSQL 13+)
-- Apply as the application role:
--   PGPASSWORD=... psql -h 127.0.0.1 -U atlas -d atlas -f database/schema.sql
-- The script is idempotent (IF NOT EXISTS) so it is safe to run again.
-- Timestamps are epoch milliseconds (BIGINT, UTC); 0/1 flags are SMALLINT.

CREATE TABLE IF NOT EXISTS users (
  id            INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  email         TEXT NOT NULL DEFAULT '',
  role          TEXT NOT NULL CHECK (role IN ('admin','analyst','viewer')),
  password_hash TEXT NOT NULL,
  active        SMALLINT NOT NULL DEFAULT 1,
  must_change   SMALLINT NOT NULL DEFAULT 0,
  created_at    BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS decoys (
  id         INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name       TEXT NOT NULL UNIQUE,
  protocol   TEXT NOT NULL,
  host       TEXT NOT NULL,
  port       INTEGER NOT NULL,
  segment    TEXT NOT NULL,
  health     TEXT NOT NULL DEFAULT 'online' CHECK (health IN ('online','degraded')),
  enabled    SMALLINT NOT NULL DEFAULT 1,
  notes      TEXT NOT NULL DEFAULT '',
  created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
  id             INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name           TEXT NOT NULL UNIQUE,
  code           TEXT NOT NULL,
  match_type     TEXT NOT NULL,
  metric         TEXT NOT NULL CHECK (metric IN ('count','attempts','distinct')),
  op             TEXT NOT NULL CHECK (op IN ('>','>=')),
  threshold      INTEGER NOT NULL,
  window_s       INTEGER NOT NULL,
  group_by       TEXT NOT NULL DEFAULT 'source_ip',
  severity       TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
  notify         TEXT NOT NULL DEFAULT 'Dashboard',
  condition_text TEXT NOT NULL DEFAULT '',
  enabled        SMALLINT NOT NULL DEFAULT 1,
  created_at     BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ts         BIGINT NOT NULL,
  severity   TEXT NOT NULL,
  decoy_id   INTEGER NOT NULL REFERENCES decoys(id) ON DELETE CASCADE,
  src_ip     TEXT NOT NULL,
  country    TEXT NOT NULL DEFAULT '??',
  protocol   TEXT NOT NULL,
  type_key   TEXT NOT NULL,
  category   TEXT NOT NULL,
  summary    TEXT NOT NULL,
  attempts   INTEGER NOT NULL DEFAULT 1,
  distinct_n INTEGER NOT NULL DEFAULT 0,
  duration_s INTEGER NOT NULL DEFAULT 0,
  payload    TEXT NOT NULL DEFAULT '',
  detected   SMALLINT NOT NULL DEFAULT 0,
  simulated  SMALLINT NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_events_ts    ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src   ON events(src_ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_decoy ON events(decoy_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_type  ON events(type_key, src_ip, ts);

CREATE TABLE IF NOT EXISTS rule_hits (
  id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  rule_id  INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
  event_id BIGINT NOT NULL,
  src_ip   TEXT NOT NULL,
  ts       BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hits_rule_ts ON rule_hits(rule_id, ts);

CREATE TABLE IF NOT EXISTS alerts (
  id              INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  code            TEXT NOT NULL,
  title           TEXT NOT NULL,
  severity        TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged','resolved')),
  owner_id        INTEGER REFERENCES users(id) ON DELETE SET NULL,
  rule_id         INTEGER REFERENCES rules(id) ON DELETE SET NULL,
  decoy_id        INTEGER REFERENCES decoys(id) ON DELETE SET NULL,
  event_id        BIGINT,
  src_ip          TEXT NOT NULL DEFAULT '',
  created_at      BIGINT NOT NULL,
  acknowledged_at BIGINT,
  resolved_at     BIGINT,
  manual          SMALLINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_status     ON alerts(status, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_decoy ON alerts(rule_id, decoy_id, created_at);

CREATE TABLE IF NOT EXISTS audit_log (
  id     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ts     BIGINT NOT NULL,
  actor  TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  ip     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

CREATE TABLE IF NOT EXISTS blocked_ips (
  ip         TEXT PRIMARY KEY,
  reason     TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL DEFAULT '',
  created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
  id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ts       BIGINT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info',
  text     TEXT NOT NULL,
  link     TEXT NOT NULL DEFAULT '',
  is_read  SMALLINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
