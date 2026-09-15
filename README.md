# sqlite-guard

Egress firewall and audit log for [sqlite-ai](https://github.com/sqliteai) agent systems.

Classify data, enforce policies, log every byte that leaves the device — from `npm install`.

```
npm install sqlite-guard
```

## Why

The sqlite-ai stack gives agents inference, memory, vectors, sync, and tools. None of it answers the question: **what data left the device, when, classified how, and was that allowed?**

sqlite-guard is the missing trust layer. It sits between your agent logic and every outbound path, enforcing policies before data moves and logging decisions after.

```
  Your Agent (adam · sqlite-agent · sqlite-mcp · sqlite-ai)
                          │
                    sqlite-guard
        ┌─────────┬───────┴──────┬───────────────┐
        │Classify │   Policy     │  Audit Log    │
        │         │   Engine     │  (SQLite)     │
        └─────────┴──────┬───────┴───────────────┘
                         │
                ALLOW / BLOCK / REDACT
                         │
              outbound path (cloud LLM, MCP, HTTP)
```

## Quick start

```typescript
import { Guard } from 'sqlite-guard';

const guard = new Guard({
  db_path: './guard-audit.db',     // persists audit log; omit for :memory:
  policy: {
    name: 'default',
    rules: [
      // SSNs, private keys, credit cards → never send anywhere
      { classification: 'RESTRICTED', action: 'block', log: true },

      // Emails, API keys, passwords → redact before sending to cloud LLMs
      { classification: 'SENSITIVE', destinations: ['cloud_llm'], action: 'redact', log: true },

      // Internal paths, hostnames → allow but log
      { classification: 'INTERNAL', action: 'allow', log: true },
    ],
    default_action: 'allow',
    default_log: true,
  },
});
```

### Classify content

```typescript
const result = guard.classify('Patient John Doe, SSN 123-45-6789, owes $50k');
// → {
//     classification: 'RESTRICTED',
//     detected: [
//       { type: 'ssn', value: '123-45-6789', start: 26, end: 37, confidence: 0.95 }
//     ],
//     reasons: ['ssn: matched "123-45-6789" → RESTRICTED']
//   }
```

### Check before sending

```typescript
const decision = guard.check(
  'Summarize this patient record: John Doe, SSN 123-45-6789',
  { destination: 'cloud_llm', agent_id: 'agent-001', run_id: 'run-42' }
);
// → { action: 'block', classification: 'RESTRICTED', ... }
```

### Guard any outbound call

```typescript
const { result, decision } = guard.guarded(
  'What are the revenue trends for user alice@acme.com?',
  { destination: 'cloud_llm', agent_id: 'agent-001' },
  (approvedContent) => {
    // This only runs if policy allows. Content may be redacted.
    return callMyLLM(approvedContent);
  }
);

if (decision.action === 'redact') {
  // approvedContent was: "What are the revenue trends for user [EMAIL]?"
}
```

### Wrap adam calls directly

```typescript
import Database from 'better-sqlite3';

// Open a database that has adam loaded as an extension
const adamDb = new Database('agent.db');
adamDb.loadExtension('./adam');

const adam = guard.wrapAdam(adamDb);

// Every call classifies → checks policy → audits → executes (or blocks)
const result = adam.adam('Summarize quarterly revenue', {
  destination: 'cloud_llm',
  agent_id: 'finance-agent',
});

if (result.allowed) {
  console.log(result.response);
} else {
  console.log('Blocked:', result.decision.reasons);
}
```

### Query the audit log

```typescript
// What got blocked in the last 24 hours?
const blocked = guard.queryAudit({
  since: new Date(Date.now() - 86_400_000).toISOString(),
  decision: 'block',
});

// Aggregate summary
const summary = guard.summarizeAudit('2026-09-01');
// → {
//     total: 1847,
//     by_decision: { allow: 1602, block: 89, redact: 156 },
//     by_classification: { PUBLIC: 1200, INTERNAL: 302, SENSITIVE: 256, RESTRICTED: 89 },
//     blocked_count: 89,
//     redacted_count: 156,
//     ...
//   }
```

### Advanced: raw SQL on the audit database

```typescript
// The audit log is a normal SQLite table — query it however you want
const rows = guard.db.prepare(`
  SELECT destination, classification, COUNT(*) as count
  FROM guard_audit
  WHERE timestamp > datetime('now', '-7 days')
  GROUP BY destination, classification
  ORDER BY count DESC
`).all();
```

## Built-in PII detection

sqlite-guard ships with pattern-based detectors for:

| Type | Classification | Examples |
|------|---------------|----------|
| `ssn` | RESTRICTED | `123-45-6789` |
| `credit_card` | RESTRICTED | `4111-1111-1111-1111` |
| `private_key` | RESTRICTED | `-----BEGIN RSA PRIVATE KEY-----` |
| `aws_secret_key` | RESTRICTED | `AWS_SECRET_ACCESS_KEY=...` |
| `email` | SENSITIVE | `alice@example.com` |
| `phone` | SENSITIVE | `(555) 123-4567` |
| `api_key` | SENSITIVE | `sk_live_abc123...` |
| `bearer_token` | SENSITIVE | `Bearer eyJhbGc...` |
| `credential` | SENSITIVE | `password=hunter2` |
| `connection_string` | SENSITIVE | `postgres://user:pass@host/db` |
| `file_path` | INTERNAL | `/Users/alice/Documents/...` |
| `hostname` | INTERNAL | `api.corp.internal` |

Add custom patterns:

```typescript
const guard = new Guard({
  policy: { /* ... */ },
  custom_patterns: [
    {
      name: 'employee_id',
      type: 'employee_id',
      pattern: /\bEMP-\d{6}\b/g,
      classification: 'SENSITIVE',
      confidence: 0.9,
    },
  ],
});
```

## Composing with the sqlite-ai stack

sqlite-guard is designed to layer on top of the [sqlite-ai](https://github.com/sqliteai) ecosystem:

| Extension | How guard composes |
|---|---|
| [adam](https://github.com/sqliteai/adam) | `guard.wrapAdam(db)` — wraps adam() / adam_ask() / adam_sql() with policy enforcement |
| [sqlite-ai](https://github.com/sqliteai/sqlite-ai) | Guard checks prompts before `ai_complete()` calls to cloud or local models |
| [sqlite-agent](https://github.com/sqliteai/sqlite-agent) | Use `guard.guarded()` around agent execution steps |
| [sqlite-mcp](https://github.com/sqliteai/sqlite-mcp) | Intercept MCP tool calls that send data to external services |
| [sqlite-memory](https://github.com/sqliteai/sqlite-memory) | Classify content at ingestion time; guard the retrieval path |
| [sqlite-columnar](https://github.com/sqliteai/sqlite-columnar) | Layer columnar analytics on guard_audit for fast compliance reports |
| [sqlite-sync](https://github.com/sqliteai/sqlite-sync) | Policy-check what data is eligible for sync to cloud |

## Architecture

- **Classifier** — regex-based PII detection with extensible patterns. Returns severity classification + detected entities with positions.
- **PolicyEngine** — evaluates ordered rules: classification × destination → action. First match wins. Supports allow, block, redact, ask, log_only.
- **AuditLog** — writes every decision to a SQLite table with content hashes (never raw content), classifications, decisions, agent/run context.
- **AdamAdapter** — wraps adam SQL functions with classify → evaluate → audit → execute pipeline.
- **Guard** — top-level API composing all of the above.

The audit log stores content *hashes*, not raw content. The guard database itself never becomes a sensitive data liability.

## License

Apache-2.0
