import crypto from 'node:crypto';
import type { Database } from 'better-sqlite3';
import type {
  AuditEntry,
  AuditQuery,
  AuditSummary,
  PolicyAction,
  PolicyDecision,
  GuardContext,
  Classification,
} from '../types.js';

export class AuditLog {
  private readonly db: Database;
  private readonly insertStmt: ReturnType<Database['prepare']>;

  constructor(db: Database) {
    this.db = db;
    this.insertStmt = db.prepare(`
      INSERT INTO guard_audit
        (id, agent_id, run_id, destination, classification, decision,
         rule_index, content_hash, content_length, detected_types,
         redacted, metadata)
      VALUES
        (@id, @agent_id, @run_id, @destination, @classification, @decision,
         @rule_index, @content_hash, @content_length, @detected_types,
         @redacted, @metadata)
    `);
  }

  /**
   * Record a policy decision in the audit log.
   */
  record(
    content: string,
    decision: PolicyDecision,
    context: GuardContext
  ): AuditEntry {
    const entry: AuditEntry = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      agent_id: context.agent_id ?? null,
      run_id: context.run_id ?? null,
      destination: context.destination,
      classification: decision.classification,
      decision: decision.action,
      rule_index: decision.rule_index,
      content_hash: hashContent(content),
      content_length: content.length,
      detected_types: decision.detected.map(d => d.type),
      redacted: decision.redacted_content !== null,
      metadata: context.metadata ?? {},
    };

    this.insertStmt.run({
      id: entry.id,
      agent_id: entry.agent_id,
      run_id: entry.run_id,
      destination: entry.destination,
      classification: entry.classification,
      decision: entry.decision,
      rule_index: entry.rule_index,
      content_hash: entry.content_hash,
      content_length: entry.content_length,
      detected_types: JSON.stringify(entry.detected_types),
      redacted: entry.redacted ? 1 : 0,
      metadata: JSON.stringify(entry.metadata),
    });

    return entry;
  }

  /**
   * Query audit entries with filters.
   */
  query(filters: AuditQuery = {}): AuditEntry[] {
    const conditions: string[] = [];
    const params: Record<string, unknown> = {};

    if (filters.since) {
      conditions.push('timestamp >= @since');
      params.since = filters.since instanceof Date
        ? filters.since.toISOString()
        : filters.since;
    }
    if (filters.until) {
      conditions.push('timestamp <= @until');
      params.until = filters.until instanceof Date
        ? filters.until.toISOString()
        : filters.until;
    }
    if (filters.agent_id) {
      conditions.push('agent_id = @agent_id');
      params.agent_id = filters.agent_id;
    }
    if (filters.run_id) {
      conditions.push('run_id = @run_id');
      params.run_id = filters.run_id;
    }
    if (filters.destination) {
      conditions.push('destination = @destination');
      params.destination = filters.destination;
    }
    if (filters.classification) {
      conditions.push('classification = @classification');
      params.classification = filters.classification;
    }
    if (filters.decision) {
      conditions.push('decision = @decision');
      params.decision = filters.decision;
    }

    const where = conditions.length > 0
      ? `WHERE ${conditions.join(' AND ')}`
      : '';

    const limit = filters.limit ?? 100;
    const offset = filters.offset ?? 0;

    const sql = `
      SELECT * FROM guard_audit
      ${where}
      ORDER BY timestamp DESC
      LIMIT @limit OFFSET @offset
    `;

    const rows = this.db.prepare(sql).all({ ...params, limit, offset }) as RawAuditRow[];
    return rows.map(deserializeRow);
  }

  /**
   * Aggregate summary over a time period.
   */
  summarize(since?: string | Date, until?: string | Date): AuditSummary {
    const conditions: string[] = [];
    const params: Record<string, unknown> = {};

    if (since) {
      conditions.push('timestamp >= @since');
      params.since = since instanceof Date ? since.toISOString() : since;
    }
    if (until) {
      conditions.push('timestamp <= @until');
      params.until = until instanceof Date ? until.toISOString() : until;
    }

    const where = conditions.length > 0
      ? `WHERE ${conditions.join(' AND ')}`
      : '';

    const total = this.db.prepare(
      `SELECT COUNT(*) as count FROM guard_audit ${where}`
    ).get(params) as { count: number };

    const byDecision = this.db.prepare(
      `SELECT decision, COUNT(*) as count FROM guard_audit ${where} GROUP BY decision`
    ).all(params) as { decision: PolicyAction; count: number }[];

    const byClassification = this.db.prepare(
      `SELECT classification, COUNT(*) as count FROM guard_audit ${where} GROUP BY classification`
    ).all(params) as { classification: Classification; count: number }[];

    const byDestination = this.db.prepare(
      `SELECT destination, COUNT(*) as count FROM guard_audit ${where} GROUP BY destination`
    ).all(params) as { destination: string; count: number }[];

    const bounds = this.db.prepare(
      `SELECT MIN(timestamp) as start, MAX(timestamp) as end FROM guard_audit ${where}`
    ).get(params) as { start: string | null; end: string | null };

    return {
      total: total.count,
      by_decision: Object.fromEntries(byDecision.map(r => [r.decision, r.count])) as Record<PolicyAction, number>,
      by_classification: Object.fromEntries(byClassification.map(r => [r.classification, r.count])) as Record<Classification, number>,
      by_destination: Object.fromEntries(byDestination.map(r => [r.destination, r.count])),
      blocked_count: byDecision.find(r => r.decision === 'block')?.count ?? 0,
      redacted_count: byDecision.find(r => r.decision === 'redact')?.count ?? 0,
      period_start: bounds.start ?? new Date().toISOString(),
      period_end: bounds.end ?? new Date().toISOString(),
    };
  }
}

// ── Helpers ─────────────────────────────────────────────────────────

interface RawAuditRow {
  id: string;
  timestamp: string;
  agent_id: string | null;
  run_id: string | null;
  destination: string;
  classification: string;
  decision: string;
  rule_index: number | null;
  content_hash: string;
  content_length: number;
  detected_types: string;
  redacted: number;
  metadata: string;
  created_at: string;
}

function deserializeRow(row: RawAuditRow): AuditEntry {
  return {
    ...row,
    classification: row.classification as Classification,
    decision: row.decision as PolicyAction,
    detected_types: JSON.parse(row.detected_types),
    redacted: row.redacted === 1,
    metadata: JSON.parse(row.metadata),
  };
}

function hashContent(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex').slice(0, 16);
}
