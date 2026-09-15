import type BetterSqlite3 from 'better-sqlite3';
import type {
  GuardConfig,
  GuardContext,
  PolicyDefinition,
  PolicyDecision,
  ClassificationResult,
  AuditEntry,
  AuditQuery,
  AuditSummary,
} from './types.js';
import { GuardDatabase } from './db/database.js';
import { Classifier } from './classify/classifier.js';
import { ModelClassifier } from './classify/model-classifier.js';
import { PolicyEngine } from './policy/engine.js';
import { AuditLog } from './audit/log.js';
import { AdamAdapter } from './adapter/adam.js';

/**
 * SQLite Guard — egress firewall and audit log for AI agent systems.
 *
 * @example
 * ```ts
 * import { Guard } from 'sqlite-guard';
 *
 * const guard = new Guard({
 *   policy: {
 *     name: 'default',
 *     rules: [
 *       { classification: 'RESTRICTED', action: 'block', log: true },
 *       { classification: 'SENSITIVE', destinations: ['cloud_llm'], action: 'redact', log: true },
 *       { classification: 'INTERNAL', action: 'allow', log: true },
 *     ],
 *     default_action: 'allow',
 *     default_log: true,
 *   },
 * });
 *
 * // Classify content
 * const result = guard.classify('SSN: 123-45-6789');
 * // → { classification: 'RESTRICTED', detected: [...], reasons: [...] }
 *
 * // Check a specific outbound call
 * const decision = guard.check('Summarize this...', { destination: 'cloud_llm' });
 * // → { action: 'allow', classification: 'PUBLIC', ... }
 *
 * // Query audit log
 * const entries = guard.audit.query({ since: '2026-09-14', decision: 'block' });
 * ```
 */
export class Guard {
  readonly classifier: Classifier;
  readonly policy: PolicyEngine;
  readonly audit: AuditLog;

  private readonly guardDb: GuardDatabase;
  private adamAdapter: AdamAdapter | null = null;
  private modelClassifier: ModelClassifier | null = null;

  constructor(config: GuardConfig) {
    this.guardDb = new GuardDatabase(config.db_path);
    this.classifier = new Classifier(config.custom_patterns);
    this.policy = new PolicyEngine(config.policy, this.classifier);
    this.audit = new AuditLog(this.guardDb.db);

    // Initialize model classifier if configured
    if (config.model) {
      this.modelClassifier = new ModelClassifier(config.model);
    }

    // Persist the policy
    this.guardDb.db.prepare(`
      INSERT OR REPLACE INTO guard_policies (name, definition, active)
      VALUES (@name, @definition, 1)
    `).run({
      name: config.policy.name,
      definition: JSON.stringify(config.policy),
    });
  }

  // ── Model lifecycle ──────────────────────────────────────────────

  /**
   * Load the GGUF model into memory. Call once at startup.
   * The model stays resident for the lifetime of the Guard instance.
   * No-op if no model was configured.
   */
  loadModel(): void {
    if (!this.modelClassifier) return;
    this.modelClassifier.load();
    this.classifier.setModelClassifier(this.modelClassifier);
  }

  /** Whether a model classifier is loaded and active */
  get modelLoaded(): boolean {
    return this.modelClassifier !== null;
  }

  // ── Classification ──────────────────────────────────────────────

  /**
   * Classify content without enforcing policy.
   * Useful for inspection, UI display, or custom logic.
   */
  classify(content: string): ClassificationResult {
    return this.classifier.classify(content);
  }

  /**
   * Redact detected entities from content.
   */
  redact(content: string): string {
    const { detected } = this.classifier.classify(content);
    return this.classifier.redact(content, detected);
  }

  // ── Policy enforcement ──────────────────────────────────────────

  /**
   * Check content against the active policy for a destination.
   * Records the decision in the audit log.
   *
   * This is the core API: call it before any outbound data movement.
   */
  check(content: string, context: GuardContext): PolicyDecision {
    const decision = this.policy.evaluate(content, context.destination);

    this.audit.record(content, decision, context);

    if (context.metadata && this.onAuditCallback) {
      const entry = this.audit.query({ limit: 1 })[0];
      if (entry) this.onAuditCallback(entry);
    }

    return decision;
  }

  /**
   * Check and execute: if policy allows, run the callback with
   * (possibly redacted) content. If policy blocks, return null.
   */
  guarded<T>(
    content: string,
    context: GuardContext,
    fn: (approvedContent: string) => T
  ): { result: T | null; decision: PolicyDecision } {
    const decision = this.check(content, context);

    switch (decision.action) {
      case 'allow':
      case 'log_only':
        return { result: fn(content), decision };

      case 'redact':
        return {
          result: fn(decision.redacted_content ?? content),
          decision,
        };

      case 'block':
      case 'ask':
        return { result: null, decision };

      default:
        return { result: null, decision };
    }
  }

  // ── Adam integration ────────────────────────────────────────────

  /**
   * Create a guard-wrapped Adam adapter for an existing adam-loaded database.
   */
  wrapAdam(adamDb: BetterSqlite3.Database): AdamAdapter {
    this.adamAdapter = new AdamAdapter(
      adamDb,
      this.policy,
      this.audit,
    );
    return this.adamAdapter;
  }

  // ── Audit queries ───────────────────────────────────────────────

  /**
   * Query the audit log.
   */
  queryAudit(filters?: AuditQuery): AuditEntry[] {
    return this.audit.query(filters);
  }

  /**
   * Get aggregate summary of audit data.
   */
  summarizeAudit(since?: string | Date, until?: string | Date): AuditSummary {
    return this.audit.summarize(since, until);
  }

  // ── Policy management ───────────────────────────────────────────

  /**
   * Update the active policy at runtime.
   */
  updatePolicy(policy: PolicyDefinition): void {
    this.policy.updatePolicy(policy);

    this.guardDb.db.prepare(`
      INSERT OR REPLACE INTO guard_policies (name, definition, active, updated_at)
      VALUES (@name, @definition, 1, strftime('%Y-%m-%dT%H:%M:%f', 'now'))
    `).run({
      name: policy.name,
      definition: JSON.stringify(policy),
    });
  }

  // ── Lifecycle ───────────────────────────────────────────────────

  /**
   * Access the underlying SQLite database (for advanced queries,
   * sqlite-columnar integration, etc.)
   */
  get db(): BetterSqlite3.Database {
    return this.guardDb.db;
  }

  /**
   * Close the guard database.
   */
  close(): void {
    this.modelClassifier?.close();
    this.guardDb.close();
  }

  // ── Callbacks ───────────────────────────────────────────────────

  private onAuditCallback?: (entry: AuditEntry) => void;

  onAudit(callback: (entry: AuditEntry) => void): void {
    this.onAuditCallback = callback;
  }
}
