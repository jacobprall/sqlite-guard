export { Guard } from './guard.js';
export { Classifier } from './classify/classifier.js';
export { PolicyEngine } from './policy/engine.js';
export { AuditLog } from './audit/log.js';
export { AdamAdapter } from './adapter/adam.js';
export { BUILTIN_PATTERNS } from './classify/patterns.js';

export type {
  // Classification
  Classification,
  ClassificationResult,
  DetectedEntity,
  PatternDefinition,

  // Policy
  PolicyDefinition,
  PolicyRule,
  PolicyAction,
  PolicyDecision,
  Destination,

  // Audit
  AuditEntry,
  AuditQuery,
  AuditSummary,

  // Guard
  GuardConfig,
  GuardContext,

  // Adam
  AdamConfig,
  AdamCallOptions,
} from './types.js';

export { CLASSIFICATION_SEVERITY } from './types.js';
export type { GuardedResult } from './adapter/adam.js';
