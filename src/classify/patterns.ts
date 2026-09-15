import type { PatternDefinition } from '../types.js';

/**
 * Built-in patterns for detecting sensitive content.
 *
 * Each pattern produces a classification. When multiple patterns match,
 * the highest-severity classification wins.
 *
 * These are intentionally conservative (high precision, moderate recall).
 * False negatives are less dangerous than false positives in a firewall:
 * a missed detection is caught by the default-block policy; a false
 * positive blocks legitimate work.
 */

export const BUILTIN_PATTERNS: PatternDefinition[] = [
  // ── RESTRICTED — never send ──────────────────────────────────────

  {
    name: 'ssn',
    type: 'ssn',
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    classification: 'RESTRICTED',
    confidence: 0.95,
  },
  {
    name: 'credit_card',
    type: 'credit_card',
    pattern: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{3,4}\b/g,
    classification: 'RESTRICTED',
    confidence: 0.9,
  },
  {
    name: 'private_key_pem',
    type: 'private_key',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    classification: 'RESTRICTED',
    confidence: 0.99,
  },
  {
    name: 'aws_secret_key',
    type: 'api_key',
    pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*[A-Za-z0-9/+=]{40}/g,
    classification: 'RESTRICTED',
    confidence: 0.95,
  },

  // ── SENSITIVE — redact or block depending on destination ─────────

  {
    name: 'email',
    type: 'email',
    pattern: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
    classification: 'SENSITIVE',
    confidence: 0.9,
  },
  {
    name: 'phone_us',
    type: 'phone',
    pattern: /\b(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b/g,
    classification: 'SENSITIVE',
    confidence: 0.7,
  },
  {
    name: 'ip_address',
    type: 'ip_address',
    pattern: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    classification: 'SENSITIVE',
    confidence: 0.6,
  },
  {
    name: 'api_key_generic',
    type: 'api_key',
    pattern: /\b(?:sk|pk|api[_-]?key|token|secret)[_-]?[a-zA-Z0-9]{20,}\b/gi,
    classification: 'SENSITIVE',
    confidence: 0.7,
  },
  {
    name: 'bearer_token',
    type: 'api_key',
    pattern: /Bearer\s+[a-zA-Z0-9._~+/=-]{20,}/g,
    classification: 'SENSITIVE',
    confidence: 0.85,
  },
  {
    name: 'password_in_text',
    type: 'credential',
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*\S+/gi,
    classification: 'SENSITIVE',
    confidence: 0.8,
  },
  {
    name: 'connection_string',
    type: 'credential',
    pattern: /(?:postgres|mysql|mongodb|redis|amqp):\/\/[^\s]+/gi,
    classification: 'SENSITIVE',
    confidence: 0.9,
  },

  // ── INTERNAL — log but typically allow ────────────────────────────

  {
    name: 'file_path_absolute',
    type: 'file_path',
    pattern: /(?:\/(?:Users|home|var|etc|opt)\/[^\s,;'")\]]+)/g,
    classification: 'INTERNAL',
    confidence: 0.5,
  },
  {
    name: 'hostname_internal',
    type: 'hostname',
    pattern: /\b(?:[a-z0-9-]+\.(?:local|internal|corp|lan|intranet))\b/gi,
    classification: 'INTERNAL',
    confidence: 0.6,
  },
];
