// ── Classification ──────────────────────────────────────────────────

export type Classification =
  | 'PUBLIC'
  | 'INTERNAL'
  | 'SENSITIVE'
  | 'RESTRICTED';

export const CLASSIFICATION_SEVERITY: Record<Classification, number> = {
  PUBLIC: 0,
  INTERNAL: 1,
  SENSITIVE: 2,
  RESTRICTED: 3,
};

export interface DetectedEntity {
  type: string;
  value: string;
  start: number;
  end: number;
  confidence: number;
}

export interface ClassificationResult {
  classification: Classification;
  detected: DetectedEntity[];
  reasons: string[];
}

// ── Destinations ────────────────────────────────────────────────────

export type Destination =
  | 'cloud_llm'
  | 'mcp_tool'
  | 'http'
  | 'sync'
  | 'filesystem'
  | (string & {});

// ── Policy ──────────────────────────────────────────────────────────

export type PolicyAction =
  | 'allow'
  | 'block'
  | 'redact'
  | 'ask'
  | 'log_only';

export interface PolicyRule {
  classification: Classification | Classification[];
  destinations?: Destination[];
  action: PolicyAction;
  log?: boolean;
}

export interface PolicyDefinition {
  name: string;
  rules: PolicyRule[];
  default_action: PolicyAction;
  default_log: boolean;
}

export interface PolicyDecision {
  action: PolicyAction;
  rule_index: number | null;
  classification: Classification;
  destination: Destination;
  detected: DetectedEntity[];
  redacted_content: string | null;
  reasons: string[];
}

// ── Audit ───────────────────────────────────────────────────────────

export interface AuditEntry {
  id: string;
  timestamp: string;
  agent_id: string | null;
  run_id: string | null;
  destination: Destination;
  classification: Classification;
  decision: PolicyAction;
  rule_index: number | null;
  content_hash: string;
  content_length: number;
  detected_types: string[];
  redacted: boolean;
  metadata: Record<string, unknown>;
}

export interface AuditQuery {
  since?: string | Date;
  until?: string | Date;
  agent_id?: string;
  run_id?: string;
  destination?: Destination;
  classification?: Classification;
  decision?: PolicyAction;
  limit?: number;
  offset?: number;
}

export interface AuditSummary {
  total: number;
  by_decision: Record<PolicyAction, number>;
  by_classification: Record<Classification, number>;
  by_destination: Record<string, number>;
  blocked_count: number;
  redacted_count: number;
  period_start: string;
  period_end: string;
}

// ── Guard context (passed per-call) ─────────────────────────────────

export interface GuardContext {
  agent_id?: string;
  run_id?: string;
  destination: Destination;
  metadata?: Record<string, unknown>;
}

// ── Adam / sqlite-ai adapter types ──────────────────────────────────

export interface AdamConfig {
  provider: string;
  api_key?: string;
  model?: string;
  [key: string]: unknown;
}

export interface AdamCallOptions extends GuardContext {
  session_id?: string;
}

// ── Guard configuration ─────────────────────────────────────────────

export interface GuardConfig {
  /** Path to the SQLite database for audit logs. Defaults to :memory: */
  db_path?: string;

  /** Active policy definition */
  policy: PolicyDefinition;

  /** Custom classification patterns beyond the built-ins */
  custom_patterns?: PatternDefinition[];

  /** Local GGUF model config for AI-powered classification via sqlite-ai */
  model?: {
    /** Path to the sqlite-ai extension binary (without file extension) */
    extension_path: string;
    /** Path to the GGUF model file */
    model_path: string;
    /** GPU layers (0 = CPU only, default 0) */
    gpu_layers?: number;
  };

  /** Path to the adam SQLite database to wrap */
  adam_db_path?: string;

  /** Callback invoked when action is 'ask' — must return allow or block */
  on_ask?: (decision: PolicyDecision, content: string) => Promise<PolicyAction>;

  /** Callback invoked on every audit entry (for real-time monitoring) */
  on_audit?: (entry: AuditEntry) => void;
}

// ── Pattern definitions ─────────────────────────────────────────────

export interface PatternDefinition {
  name: string;
  type: string;
  pattern: RegExp;
  classification: Classification;
  confidence?: number;
}
