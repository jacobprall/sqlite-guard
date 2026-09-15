import type { Database } from 'better-sqlite3';
import type { PolicyDecision, AdamCallOptions, PolicyAction } from '../types.js';
import type { PolicyEngine } from '../policy/engine.js';
import type { AuditLog } from '../audit/log.js';

/**
 * Wraps an adam-loaded SQLite database with guard policy enforcement.
 *
 * adam exposes SQL functions: adam(), adam_ask(), adam_sql(), adam_config().
 * This adapter intercepts calls, classifies the prompt content, evaluates
 * the active policy, logs the decision, and only forwards to adam if allowed.
 *
 * Usage:
 *   const adamDb = new Database('agent.db');
 *   // ... load adam extension into adamDb ...
 *   const adapter = new AdamAdapter(adamDb, policyEngine, auditLog);
 *   const result = await adapter.adam('Summarize revenue', { destination: 'cloud_llm' });
 */
export class AdamAdapter {
  private readonly onAsk?: (decision: PolicyDecision, content: string) => Promise<PolicyAction>;

  constructor(
    private readonly adamDb: Database,
    private readonly policy: PolicyEngine,
    private readonly audit: AuditLog,
    onAsk?: (decision: PolicyDecision, content: string) => Promise<PolicyAction>,
  ) {
    this.onAsk = onAsk;
  }

  /**
   * Guard-wrapped adam() — stateless one-shot chat.
   * Evaluates policy before forwarding to adam.
   */
  adam(prompt: string, options: AdamCallOptions): GuardedResult {
    return this.guarded(prompt, options, () => {
      const row = this.adamDb
        .prepare(`SELECT adam(?) as response`)
        .get(prompt) as { response: string } | undefined;
      return row?.response ?? null;
    });
  }

  /**
   * Guard-wrapped adam_ask() — SQL-aware agent.
   * Evaluates policy before forwarding to adam_ask.
   */
  adamAsk(prompt: string, options: AdamCallOptions): GuardedResult {
    return this.guarded(prompt, options, () => {
      const row = this.adamDb
        .prepare(`SELECT adam_ask(?) as response`)
        .get(prompt) as { response: string } | undefined;
      return row?.response ?? null;
    });
  }

  /**
   * Guard-wrapped adam_sql() — natural language to SQL.
   * Evaluates policy before forwarding to adam_sql.
   */
  adamSql(question: string, options: AdamCallOptions): GuardedResult {
    return this.guarded(question, options, () => {
      const row = this.adamDb
        .prepare(`SELECT adam_sql(?) as response`)
        .get(question) as { response: string } | undefined;
      return row?.response ?? null;
    });
  }

  /**
   * Core guarded execution: classify → evaluate policy → audit → execute or block.
   */
  private guarded(
    content: string,
    options: AdamCallOptions,
    execute: () => string | null
  ): GuardedResult {
    const destination = options.destination ?? 'cloud_llm';
    const decision = this.policy.evaluate(content, destination);

    const entry = this.audit.record(content, decision, {
      destination,
      agent_id: options.agent_id,
      run_id: options.run_id,
      metadata: options.metadata,
    });

    switch (decision.action) {
      case 'allow':
      case 'log_only':
        return {
          allowed: true,
          response: execute(),
          decision,
          audit_id: entry.id,
        };

      case 'redact': {
        const redacted = decision.redacted_content ?? content;
        const redactedExec = () => {
          const row = this.adamDb
            .prepare(`SELECT adam(?) as response`)
            .get(redacted) as { response: string } | undefined;
          return row?.response ?? null;
        };
        return {
          allowed: true,
          response: redactedExec(),
          decision,
          audit_id: entry.id,
          redacted_prompt: redacted,
        };
      }

      case 'ask':
        // If no onAsk callback, treat as block and flag for approval
        if (this.onAsk) {
          // onAsk is async — callers of the sync adapter must handle
          // the requires_approval flag and call onAsk externally
        }
        return {
          allowed: false,
          response: null,
          decision,
          audit_id: entry.id,
          requires_approval: true,
        };

      case 'block':
        return {
          allowed: false,
          response: null,
          decision,
          audit_id: entry.id,
        };

      default:
        return {
          allowed: false,
          response: null,
          decision,
          audit_id: entry.id,
        };
    }
  }
}

export interface GuardedResult {
  allowed: boolean;
  response: string | null;
  decision: PolicyDecision;
  audit_id: string;
  redacted_prompt?: string;
  requires_approval?: boolean;
}
