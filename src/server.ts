import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { serve } from '@hono/node-server';
import { Guard } from './guard.js';
import type {
  GuardContext,
  PolicyDefinition,
  AuditQuery,
  Classification,
  PolicyAction,
  Destination,
} from './types.js';

// ── Config ──────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT ?? '3000', 10);
const DB_DIR = process.env.GUARD_DB_DIR ?? '/var/data';
const DB_PATH = `${DB_DIR}/guard-audit.db`;

const DEFAULT_POLICY: PolicyDefinition = {
  name: 'default',
  rules: [
    { classification: 'RESTRICTED', action: 'block', log: true },
    { classification: 'SENSITIVE', destinations: ['cloud_llm'], action: 'redact', log: true },
    { classification: 'SENSITIVE', destinations: ['mcp_tool'], action: 'allow', log: true },
    { classification: 'INTERNAL', action: 'allow', log: true },
  ],
  default_action: 'allow',
  default_log: true,
};

// ── Guard instance ──────────────────────────────────────────────────

console.log(`[guard] Initializing with audit database at ${DB_PATH}`);
const guard = new Guard({
  db_path: DB_PATH,
  policy: DEFAULT_POLICY,
});
console.log(`[guard] Ready`);

// ── App ─────────────────────────────────────────────────────────────

const app = new Hono();

app.use('*', cors());

// ── Health ──────────────────────────────────────────────────────────

app.get('/', (c) => {
  return c.json({
    service: 'sqlite-guard',
    status: 'ok',
    version: '0.1.0',
    description: 'Egress firewall and audit log for AI agent systems',
    endpoints: {
      'POST /classify': 'Classify content for PII / sensitivity',
      'POST /check': 'Check content against policy for a destination',
      'POST /redact': 'Redact sensitive entities from content',
      'GET  /audit': 'Query the audit log',
      'GET  /audit/summary': 'Aggregate audit summary',
      'POST /policy': 'Update the active policy',
      'GET  /policy': 'Get the active policy',
    },
  });
});

app.get('/health', (c) => {
  return c.json({ status: 'ok' });
});

// ── Classify ────────────────────────────────────────────────────────

app.post('/classify', async (c) => {
  const body = await c.req.json<{ content: string }>();
  if (!body.content) {
    return c.json({ error: 'Missing required field: content' }, 400);
  }

  const result = guard.classify(body.content);
  return c.json(result);
});

// ── Check ───────────────────────────────────────────────────────────

app.post('/check', async (c) => {
  const body = await c.req.json<{
    content: string;
    destination: Destination;
    agent_id?: string;
    run_id?: string;
    metadata?: Record<string, unknown>;
  }>();

  if (!body.content || !body.destination) {
    return c.json({ error: 'Missing required fields: content, destination' }, 400);
  }

  const context: GuardContext = {
    destination: body.destination,
    agent_id: body.agent_id,
    run_id: body.run_id,
    metadata: body.metadata,
  };

  const decision = guard.check(body.content, context);
  return c.json(decision);
});

// ── Redact ──────────────────────────────────────────────────────────

app.post('/redact', async (c) => {
  const body = await c.req.json<{ content: string }>();
  if (!body.content) {
    return c.json({ error: 'Missing required field: content' }, 400);
  }

  const redacted = guard.redact(body.content);
  return c.json({ original_length: body.content.length, redacted });
});

// ── Audit query ─────────────────────────────────────────────────────

app.get('/audit', (c) => {
  const query: AuditQuery = {};

  const since = c.req.query('since');
  const until = c.req.query('until');
  const agent_id = c.req.query('agent_id');
  const run_id = c.req.query('run_id');
  const destination = c.req.query('destination');
  const classification = c.req.query('classification');
  const decision = c.req.query('decision');
  const limit = c.req.query('limit');
  const offset = c.req.query('offset');

  if (since) query.since = since;
  if (until) query.until = until;
  if (agent_id) query.agent_id = agent_id;
  if (run_id) query.run_id = run_id;
  if (destination) query.destination = destination as Destination;
  if (classification) query.classification = classification as Classification;
  if (decision) query.decision = decision as PolicyAction;
  if (limit) query.limit = parseInt(limit, 10);
  if (offset) query.offset = parseInt(offset, 10);

  const entries = guard.queryAudit(query);
  return c.json({ count: entries.length, entries });
});

// ── Audit summary ───────────────────────────────────────────────────

app.get('/audit/summary', (c) => {
  const since = c.req.query('since');
  const until = c.req.query('until');
  const summary = guard.summarizeAudit(since ?? undefined, until ?? undefined);
  return c.json(summary);
});

// ── Policy management ───────────────────────────────────────────────

app.get('/policy', (c) => {
  return c.json(guard.policy.getPolicy());
});

app.post('/policy', async (c) => {
  const policy = await c.req.json<PolicyDefinition>();
  if (!policy.name || !policy.rules) {
    return c.json({ error: 'Invalid policy: requires name and rules' }, 400);
  }
  guard.updatePolicy(policy);
  return c.json({ status: 'updated', policy });
});

// ── Start ───────────────────────────────────────────────────────────

console.log(`[guard] Starting server on 0.0.0.0:${PORT}`);
serve({ fetch: app.fetch, hostname: '0.0.0.0', port: PORT }, (info) => {
  console.log(`[guard] Listening on http://0.0.0.0:${info.port}`);
});
