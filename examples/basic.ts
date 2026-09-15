/**
 * Basic sqlite-guard usage — classify, check, and audit.
 *
 * Run: npx tsx examples/basic.ts
 */
import { Guard } from '../src/index.js';

const guard = new Guard({
  policy: {
    name: 'demo',
    rules: [
      { classification: 'RESTRICTED', action: 'block', log: true },
      { classification: 'SENSITIVE', destinations: ['cloud_llm'], action: 'redact', log: true },
      { classification: 'SENSITIVE', destinations: ['mcp_tool'], action: 'allow', log: true },
      { classification: 'INTERNAL', action: 'allow', log: true },
    ],
    default_action: 'allow',
    default_log: true,
  },
});

// ── Classify some content ────────────────────────────────────────

console.log('─── Classification ───');

const examples = [
  'The quarterly revenue was $2.3M with strong growth in Q3.',
  'Contact alice@acme.com for the full report.',
  'Patient SSN: 123-45-6789, DOB: 1990-01-15',
  'Connect to postgres://admin:s3cret@db.internal:5432/prod',
  'The API key is sk_test_example_not_a_real_key_1234',
  '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...',
];

for (const text of examples) {
  const result = guard.classify(text);
  console.log(`\n  "${text.slice(0, 60)}..."`);
  console.log(`  → ${result.classification}`);
  if (result.detected.length > 0) {
    console.log(`    detected: ${result.detected.map(d => d.type).join(', ')}`);
  }
}

// ── Policy enforcement ───────────────────────────────────────────

console.log('\n─── Policy enforcement ───');

const checks = [
  { content: 'Summarize revenue trends for Q3 2026.', dest: 'cloud_llm' as const },
  { content: 'Send report to alice@acme.com about the project.', dest: 'cloud_llm' as const },
  { content: 'Patient record: SSN 123-45-6789', dest: 'cloud_llm' as const },
  { content: 'Check password=hunter2 in the config', dest: 'mcp_tool' as const },
];

for (const { content, dest } of checks) {
  const decision = guard.check(content, {
    destination: dest,
    agent_id: 'demo-agent',
  });
  console.log(`\n  "${content.slice(0, 50)}..." → ${dest}`);
  console.log(`  → ${decision.action.toUpperCase()} (${decision.classification})`);
  if (decision.redacted_content) {
    console.log(`    redacted: "${decision.redacted_content.slice(0, 60)}..."`);
  }
}

// ── Guarded execution ────────────────────────────────────────────

console.log('\n─── Guarded execution ───');

const { result, decision } = guard.guarded(
  'Analyze spending for user alice@acme.com this quarter',
  { destination: 'cloud_llm', agent_id: 'finance-agent' },
  (approvedContent) => {
    // This simulates a cloud LLM call — only runs if policy allows
    return `LLM response for: "${approvedContent}"`;
  }
);

console.log(`  Decision: ${decision.action}`);
console.log(`  Result: ${result}`);

// ── Audit summary ────────────────────────────────────────────────

console.log('\n─── Audit summary ───');

const summary = guard.summarizeAudit();
console.log(`  Total checks: ${summary.total}`);
console.log(`  By decision:`, summary.by_decision);
console.log(`  By classification:`, summary.by_classification);
console.log(`  Blocked: ${summary.blocked_count}`);
console.log(`  Redacted: ${summary.redacted_count}`);

guard.close();
