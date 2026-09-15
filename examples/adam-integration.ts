/**
 * sqlite-guard wrapping adam — every LLM call is policy-checked.
 *
 * Requires: adam extension binary available at ./adam
 * Run: npx tsx examples/adam-integration.ts
 */
import Database from 'better-sqlite3';
import { Guard } from '../src/index.js';

// ── Set up guard ─────────────────────────────────────────────────

const guard = new Guard({
  db_path: './guard-audit.db',
  policy: {
    name: 'production',
    rules: [
      // Never send restricted content (SSNs, private keys, credit cards)
      { classification: 'RESTRICTED', action: 'block', log: true },

      // Redact sensitive content (emails, API keys) before cloud LLM calls
      { classification: 'SENSITIVE', destinations: ['cloud_llm'], action: 'redact', log: true },

      // Allow everything else, but log it
      { classification: 'INTERNAL', action: 'allow', log: true },
      { classification: 'PUBLIC', action: 'allow', log: true },
    ],
    default_action: 'allow',
    default_log: true,
  },
});

// Real-time monitoring: get notified of every decision
guard.onAudit((entry) => {
  if (entry.decision === 'block') {
    console.warn(`⛔ BLOCKED: ${entry.classification} content → ${entry.destination}`);
  }
});

// ── Open an adam-loaded database ─────────────────────────────────

// In real usage: adamDb.loadExtension('./path/to/adam');
// and: adamDb.exec("SELECT adam_config('provider', 'anthropic')");
// For this example we'll just show the guard wrapping pattern.

const adamDb = new Database(':memory:');

// Create a mock adam() function for demonstration
adamDb.function('adam', (prompt: unknown) => {
  return `[mock adam response for: "${String(prompt).slice(0, 40)}..."]`;
});

adamDb.function('adam_ask', (prompt: unknown) => {
  return `[mock adam_ask response for: "${String(prompt).slice(0, 40)}..."]`;
});

// ── Wrap adam with guard ─────────────────────────────────────────

const adam = guard.wrapAdam(adamDb);

console.log('─── Guard-wrapped adam calls ───\n');

// Safe call — no sensitive content
const r1 = adam.adam('What were our top 5 products by revenue last quarter?', {
  destination: 'cloud_llm',
  agent_id: 'finance-agent',
  run_id: 'run-001',
});
console.log(`Call 1: ${r1.allowed ? '✅ ALLOWED' : '⛔ BLOCKED'}`);
console.log(`  Response: ${r1.response}`);
console.log(`  Classification: ${r1.decision.classification}\n`);

// Sensitive call — email will be redacted
const r2 = adam.adam('Send the Q3 report to alice@acme.com and bob@acme.com', {
  destination: 'cloud_llm',
  agent_id: 'finance-agent',
  run_id: 'run-001',
});
console.log(`Call 2: ${r2.allowed ? '✅ ALLOWED (redacted)' : '⛔ BLOCKED'}`);
console.log(`  Response: ${r2.response}`);
console.log(`  Redacted prompt: ${r2.redacted_prompt}`);
console.log(`  Classification: ${r2.decision.classification}\n`);

// Restricted call — SSN will be blocked entirely
const r3 = adam.adam('Look up the account for SSN 123-45-6789', {
  destination: 'cloud_llm',
  agent_id: 'finance-agent',
  run_id: 'run-001',
});
console.log(`Call 3: ${r3.allowed ? '✅ ALLOWED' : '⛔ BLOCKED'}`);
console.log(`  Response: ${r3.response}`);
console.log(`  Classification: ${r3.decision.classification}`);
console.log(`  Reasons: ${r3.decision.reasons.join('; ')}\n`);

// ── Print audit summary ──────────────────────────────────────────

console.log('─── Audit summary ───\n');
const summary = guard.summarizeAudit();
console.log(`  Total calls: ${summary.total}`);
console.log(`  Allowed: ${summary.by_decision.allow ?? 0}`);
console.log(`  Redacted: ${summary.redacted_count}`);
console.log(`  Blocked: ${summary.blocked_count}`);

// ── Show raw audit entries ───────────────────────────────────────

console.log('\n─── Full audit log ───\n');
const entries = guard.queryAudit();
for (const e of entries) {
  console.log(`  ${e.timestamp} | ${e.decision.padEnd(8)} | ${e.classification.padEnd(10)} | ${e.destination} | agent=${e.agent_id}`);
}

guard.close();
adamDb.close();
