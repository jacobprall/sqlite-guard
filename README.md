# sqlite-guard

**Self-hosted data classification and egress firewall for AI applications.**

Two-layer classification (regex + local GGUF model via [sqlite-ai](https://github.com/sqliteai/sqlite-ai)) runs entirely on your infrastructure. No data leaves your environment for the classification itself. Every decision is recorded in a SQLite audit log you own.

```
npm install sqlite-guard
```

---

## The problem

You're building an AI application — an agent, a RAG pipeline, a copilot, an internal tool. It handles real data: customer records, employee information, medical notes, financial reports, source code with credentials.

At some point, that data hits an outbound boundary: a cloud LLM API, an MCP tool, a sync layer, an HTTP call. The question is always the same:

> **What just left my environment, classified how, and was that allowed?**

Most teams answer this with "we trust the prompt" or "we'll add guardrails later." Regulated teams can't afford that. Privacy-conscious teams don't want to. And nobody wants to learn they shipped customer SSNs to a cloud model by reading about it in a breach disclosure.

## What sqlite-guard does

sqlite-guard is a TypeScript library that sits between your application logic and every outbound data path. For each piece of content, it:

1. **Classifies** — runs regex pattern matching (14 built-in detectors) and optionally a local GGUF model for contextual understanding
2. **Evaluates policy** — checks the classification against your rules for that destination
3. **Decides** — allow, block, redact, or ask
4. **Audits** — records the decision, classification, destination, content hash, and context to a SQLite database

The classification model runs locally via [sqlite-ai](https://github.com/sqliteai/sqlite-ai). Your data never leaves your environment to be classified. The audit log stores content hashes, never raw content — the audit database itself is not a liability.

```
┌──────────────────────────────────────────────┐
│            your application                  │
│                                              │
│   agent logic · RAG pipeline · API layer     │
│                     │                        │
│              ┌──────┴───────┐                │
│              │ sqlite-guard │                │
│              │              │                │
│   ┌──────┐  │  ┌────────┐  │  ┌──────────┐  │
│   │regex │──┼─▶│ policy │──┼─▶│audit log │  │
│   │      │  │  │ engine │  │  │ (SQLite) │  │
│   │model │──┘  └───┬────┘  │  └──────────┘  │
│   │(local│         │       │                 │
│   │ GGUF)│    allow│block  │                 │
│   └──────┘    redact│ask   │                 │
│              ┌──────┴───────┐                │
│              │   outbound   │                │
│              │  cloud LLM   │                │
│              │  MCP tool    │                │
│              │  HTTP API    │                │
│              │  sync layer  │                │
│              └──────────────┘                │
│                                              │
│         nothing leaves for classification    │
│         everything is audited                │
└──────────────────────────────────────────────┘
```

## Why self-hosted classification matters

Cloud-based PII detection (Presidio-as-a-service, cloud DLP APIs) has a structural problem: you send your data to a third party to find out if your data is sensitive. That is the thing you are trying to prevent.

sqlite-guard runs classification on your machine, your server, your infrastructure. The GGUF model loads into your process via sqlite-ai. There is no network call, no API key, no third-party data processor in the classification path.

This matters for:

- **HIPAA** — PHI cannot be sent to a classification service that isn't a covered entity or business associate
- **GDPR / EU AI Act** — data residency requirements are easier to satisfy when classification never leaves the data boundary
- **SOC 2** — your auditor wants to see what data went where; sqlite-guard produces that log
- **Legal privilege** — law firms cannot send client communications to external services for screening
- **Source code** — credentials and secrets in code should not be sent to a cloud DLP scanner to be detected
- **Enterprise data** — salary data, M&A drafts, board materials, HR records

## Classification accuracy

sqlite-guard uses two classifiers that run on every input. Results are merged — the highest severity wins.

**Layer 1: Regex patterns** — fast, deterministic, zero false negatives for known formats.

| What it catches | Examples |
|---|---|
| SSNs | `123-45-6789` |
| Credit cards | `4111-1111-1111-1111` |
| Private keys | `-----BEGIN RSA PRIVATE KEY-----` |
| API keys / tokens | `sk_live_...`, `Bearer eyJ...` |
| Emails | `alice@example.com` |
| Connection strings | `postgres://user:pass@host/db` |
| Credentials | `password=hunter2` |
| File paths, hostnames | `/Users/alice/...`, `db.corp.internal` |

**Layer 2: Local GGUF model** — catches what regex can't: context, meaning, implication.

| What it catches | Why regex misses it |
|---|---|
| Medical records without structured identifiers | "prescribed metformin for type 2 diabetes" — no pattern to match |
| Security question answers | "my mother's maiden name is Rodriguez" — contextual PII |
| Financial records | "credit score dropped to 580 after the bankruptcy" — meaning, not format |
| Salary and compensation data | "making 185k base plus 40k RSUs" — contextual sensitivity |
| Spaced or obfuscated SSNs | `1 2 3 - 4 5 - 6 7 8 9` — adversarial evasion |
| SSNs spelled as words | "one two three dash four five dash six seven eight nine" |

Tested with Qwen2.5-3B-Instruct (Q4_K_M): **9/9 correct** across easy, hard, and adversarial test cases.

## Use cases

### 1. AI agent with cloud LLM reasoning

Your agent uses a cloud model (Anthropic, OpenAI) for reasoning but handles sensitive data locally. Guard every prompt before it reaches the API.

```typescript
import { Guard } from 'sqlite-guard';
import Anthropic from '@anthropic-ai/sdk';

const guard = new Guard({
  db_path: './audit.db',
  policy: {
    name: 'agent-policy',
    rules: [
      { classification: 'RESTRICTED', action: 'block' },
      { classification: 'SENSITIVE', destinations: ['cloud_llm'], action: 'redact' },
    ],
    default_action: 'allow',
    default_log: true,
  },
  // Optional: local model for contextual classification
  model: {
    extension_path: './extensions/ai',
    model_path: './models/qwen2.5-7b-instruct-q4_k_m.gguf',
  },
});
guard.loadModel();

const anthropic = new Anthropic();

async function agentStep(prompt: string, agentId: string) {
  const { result, decision } = guard.guarded(
    prompt,
    { destination: 'cloud_llm', agent_id: agentId },
    (approved) => anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1024,
      messages: [{ role: 'user', content: approved }],
    })
  );

  if (!result) {
    console.log(`Blocked: ${decision.classification} — ${decision.reasons}`);
    return null;
  }

  return result;
}
```

If the prompt contains an SSN, it never reaches Anthropic. If it contains an email, the email is replaced with `[EMAIL]` before the API call. Both decisions are logged.

### 2. RAG pipeline — classify at ingestion and retrieval

Guard both sides: classify documents when you ingest them into your vector store, and classify the assembled context before sending it to a model.

```typescript
import { Guard } from 'sqlite-guard';

const guard = new Guard({ /* policy */ });

// At ingestion: tag documents with their classification
function ingestDocument(content: string, source: string) {
  const { classification, detected } = guard.classify(content);

  // Store classification as metadata alongside your embeddings
  vectorStore.insert({
    content,
    embedding: embed(content),
    metadata: {
      source,
      classification,
      detected_types: detected.map(d => d.type),
    },
  });
}

// At retrieval: guard the assembled context before it goes to a model
function queryWithGuard(question: string, agentId: string) {
  const chunks = vectorStore.search(question, { limit: 10 });

  const context = chunks.map(c => c.content).join('\n\n');

  const { result, decision } = guard.guarded(
    `Context:\n${context}\n\nQuestion: ${question}`,
    { destination: 'cloud_llm', agent_id: agentId },
    (approved) => callModel(approved)
  );

  return { result, decision };
}
```

### 3. MCP tool server — guard outbound tool calls

If your agent uses MCP tools that send data to external services, wrap each tool call.

```typescript
import { Guard } from 'sqlite-guard';

const guard = new Guard({
  policy: {
    name: 'mcp-policy',
    rules: [
      { classification: 'RESTRICTED', action: 'block' },
      { classification: 'SENSITIVE', destinations: ['mcp_tool'], action: 'ask' },
    ],
    default_action: 'allow',
    default_log: true,
  },
});

// Wrap any MCP tool call
function guardedToolCall(toolName: string, args: Record<string, string>, agentId: string) {
  const content = JSON.stringify(args);

  const decision = guard.check(content, {
    destination: 'mcp_tool',
    agent_id: agentId,
    metadata: { tool: toolName },
  });

  if (decision.action === 'block') {
    return { error: `Blocked: ${decision.classification} data in ${toolName} args` };
  }

  if (decision.action === 'ask') {
    // Surface to user for approval
    return { pending_approval: true, decision };
  }

  return executeTool(toolName, args);
}
```

### 4. HTTP API gateway — classify and audit all traffic

Deploy sqlite-guard as a sidecar or middleware that inspects request/response bodies.

```typescript
import { Hono } from 'hono';
import { Guard } from 'sqlite-guard';

const guard = new Guard({
  db_path: '/var/data/audit.db',
  policy: { /* your rules */ },
});

const app = new Hono();

// Middleware: classify and audit every outbound response
app.use('/api/*', async (c, next) => {
  await next();

  const body = await c.res.text();
  const decision = guard.check(body, {
    destination: 'http',
    metadata: {
      path: c.req.path,
      method: c.req.method,
      status: c.res.status,
    },
  });

  if (decision.action === 'block') {
    return c.json({ error: 'Response contained restricted data' }, 500);
  }
});
```

### 5. Compliance reporting — query the audit log

The audit log is a SQLite table. Query it with SQL, export it, feed it to your compliance tooling.

```typescript
const guard = new Guard({ db_path: './audit.db', policy: { /* ... */ } });

// What got blocked this week?
const blocked = guard.queryAudit({
  since: '2026-09-08',
  decision: 'block',
});

// Aggregate by destination and classification
const rows = guard.db.prepare(`
  SELECT
    destination,
    classification,
    decision,
    COUNT(*) as count,
    SUM(content_length) as total_bytes
  FROM guard_audit
  WHERE timestamp > datetime('now', '-30 days')
  GROUP BY destination, classification, decision
  ORDER BY count DESC
`).all();

// Summary for an auditor
const summary = guard.summarizeAudit('2026-01-01');
// → {
//   total: 48291,
//   by_decision: { allow: 41003, block: 2104, redact: 5184 },
//   by_classification: { PUBLIC: 35000, INTERNAL: 6200, SENSITIVE: 5087, RESTRICTED: 2004 },
//   blocked_count: 2104,
//   redacted_count: 5184,
// }
```

## Setup

### Regex-only (zero dependencies beyond better-sqlite3)

```typescript
import { Guard } from 'sqlite-guard';

const guard = new Guard({
  db_path: './audit.db',
  policy: { name: 'default', rules: [ /* ... */ ], default_action: 'allow', default_log: true },
});

// Ready immediately. No model to load. Regex patterns only.
guard.classify('test content');
```

### With local model (requires sqlite-ai extension + GGUF model)

```typescript
const guard = new Guard({
  db_path: './audit.db',
  policy: { /* ... */ },
  model: {
    extension_path: './extensions/ai',      // sqlite-ai binary (.dylib/.so)
    model_path: './models/qwen2.5-7b.gguf', // any GGUF model
    gpu_layers: 0,                          // 0 = CPU only
  },
});

guard.loadModel(); // loads model into memory (~2-10s depending on size)

// Now classify() uses both regex + model
guard.classify('test content');
```

**Getting the sqlite-ai extension:**

Download from [sqlite-ai releases](https://github.com/sqliteai/sqlite-ai/releases/tag/1.0.4):
- Linux: `ai-linux-cpu-x86_64-1.0.4.tar.gz`
- macOS: extract from `ai-apple-xcframework-1.0.4.zip` → `macos-arm64_x86_64/ai.framework/Versions/A/ai`

**Choosing a model:**

Any instruction-following GGUF model works. Tested options:

| Model | Size | RAM needed | Quality | Speed |
|---|---|---|---|---|
| Qwen2.5-0.5B-Instruct Q8_0 | 644MB | ~2GB | Usable, over-classifies | Fast |
| Qwen2.5-3B-Instruct Q4_K_M | 1.8GB | ~4GB | Good (9/9 gauntlet) | Moderate |
| Qwen2.5-7B-Instruct Q4_K_M | 4.7GB | ~8GB | Excellent | Production target |

### As a hosted API (Docker + Render)

The repo includes a Dockerfile and `render.yaml` for deploying as a web service with a persistent disk for the audit log.

```
docker build -t sqlite-guard .
docker run -p 3000:3000 -v ./data:/var/data sqlite-guard
```

Or deploy to Render: **[Deploy →](https://dashboard.render.com/blueprint/new?repo=https://github.com/jacobprall/sqlite-guard)**

API endpoints:

| Method | Path | Description |
|---|---|---|
| `POST` | `/classify` | Classify content, return classification + detected entities |
| `POST` | `/check` | Classify + evaluate policy + audit log |
| `POST` | `/redact` | Return content with sensitive entities replaced |
| `GET` | `/audit` | Query audit log with filters |
| `GET` | `/audit/summary` | Aggregate statistics |
| `GET/POST` | `/policy` | Read or update the active policy |
| `GET` | `/status` | Model state, DB path, audit summary |
| `GET` | `/health` | Health check |

Set `GUARD_API_KEY` to require Bearer token authentication on all endpoints except `/` and `/health`.

## Policy reference

Policies are ordered rule lists. First match wins.

```typescript
{
  name: 'production',
  rules: [
    // Block restricted data everywhere
    { classification: 'RESTRICTED', action: 'block', log: true },

    // Redact sensitive data going to cloud LLMs
    { classification: 'SENSITIVE', destinations: ['cloud_llm'], action: 'redact', log: true },

    // Allow sensitive data to local MCP tools
    { classification: 'SENSITIVE', destinations: ['mcp_tool'], action: 'allow', log: true },

    // Log internal data
    { classification: 'INTERNAL', action: 'allow', log: true },
  ],
  default_action: 'allow', // unmatched content
  default_log: true,       // log unmatched decisions
}
```

**Actions:**

| Action | Behavior |
|---|---|
| `allow` | Forward content unchanged |
| `block` | Reject — content never reaches the destination |
| `redact` | Replace detected entities with `[TYPE]` placeholders, then forward |
| `ask` | Pause and surface to the caller for approval |
| `log_only` | Forward unchanged but record in audit log |

**Destinations:** `cloud_llm`, `mcp_tool`, `http`, `sync`, `filesystem`, or any custom string.

**Classification levels** (in ascending severity):

| Level | Meaning | Examples |
|---|---|---|
| `PUBLIC` | No sensitive content | Business metrics, public documentation |
| `INTERNAL` | Reveals internal structure | File paths, internal hostnames |
| `SENSITIVE` | Contains PII or confidential data | Emails, medical records, salary data |
| `RESTRICTED` | Must never leave the environment | SSNs, credit cards, private keys |

## Architecture

```
Guard
├── Classifier
│   ├── RegexPatterns (14 built-in + custom)
│   └── ModelClassifier (optional, sqlite-ai + GGUF)
│       ├── classification cache (content-hash, 5min TTL)
│       └── llm_text_generate() via sqlite-ai
├── PolicyEngine (ordered rules, first match wins)
├── AuditLog (SQLite table, content hashes only)
└── AdamAdapter (wraps adam()/adam_ask()/adam_sql())
```

**Key design decisions:**

- The audit log stores **content hashes, never raw content**. The audit database is not a data liability.
- The model classifier uses a **separate in-memory SQLite database** from the audit database. Model inference does not touch your data store.
- Classification results are **cached by content hash** (5-minute TTL, 500 entries). Repeated content skips model inference entirely.
- Policy updates take effect **immediately** — no restart required.
- The library has **one runtime dependency**: `better-sqlite3`. The sqlite-ai extension and GGUF model are optional.

## License

Apache-2.0
