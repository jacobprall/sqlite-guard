/**
 * SQLite schema for the guard audit database.
 *
 * Designed so that sqlite-columnar can be layered on top for fast
 * aggregate analytics over millions of audit rows.
 */

export const SCHEMA_VERSION = 1;

export const MIGRATIONS: string[] = [
  /* v1 — initial schema */
  `
  CREATE TABLE IF NOT EXISTS guard_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS guard_audit (
    id               TEXT PRIMARY KEY,
    timestamp        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
    agent_id         TEXT,
    run_id           TEXT,
    destination      TEXT NOT NULL,
    classification   TEXT NOT NULL CHECK (classification IN ('PUBLIC','INTERNAL','SENSITIVE','RESTRICTED')),
    decision         TEXT NOT NULL CHECK (decision IN ('allow','block','redact','ask','log_only')),
    rule_index       INTEGER,
    content_hash     TEXT NOT NULL,
    content_length   INTEGER NOT NULL,
    detected_types   TEXT NOT NULL DEFAULT '[]',
    redacted         INTEGER NOT NULL DEFAULT 0,
    metadata         TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now'))
  );

  CREATE INDEX IF NOT EXISTS idx_guard_audit_timestamp
    ON guard_audit(timestamp);
  CREATE INDEX IF NOT EXISTS idx_guard_audit_agent
    ON guard_audit(agent_id) WHERE agent_id IS NOT NULL;
  CREATE INDEX IF NOT EXISTS idx_guard_audit_decision
    ON guard_audit(decision);
  CREATE INDEX IF NOT EXISTS idx_guard_audit_classification
    ON guard_audit(classification);
  CREATE INDEX IF NOT EXISTS idx_guard_audit_destination
    ON guard_audit(destination);

  CREATE TABLE IF NOT EXISTS guard_policies (
    name       TEXT PRIMARY KEY,
    definition TEXT NOT NULL,
    active     INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now'))
  );

  INSERT OR IGNORE INTO guard_meta (key, value)
    VALUES ('schema_version', '${SCHEMA_VERSION}');
  `,
];
