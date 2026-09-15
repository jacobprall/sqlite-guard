import { describe, it, expect } from 'vitest';
import { Classifier } from '../src/classify/classifier.js';

describe('Classifier', () => {
  const classifier = new Classifier();

  describe('classify', () => {
    it('classifies clean text as PUBLIC', () => {
      const result = classifier.classify('The quarterly revenue was strong.');
      expect(result.classification).toBe('PUBLIC');
      expect(result.detected).toHaveLength(0);
    });

    it('detects SSN as RESTRICTED', () => {
      const result = classifier.classify('SSN: 123-45-6789');
      expect(result.classification).toBe('RESTRICTED');
      expect(result.detected).toHaveLength(1);
      expect(result.detected[0].type).toBe('ssn');
      expect(result.detected[0].value).toBe('123-45-6789');
    });

    it('detects credit card as RESTRICTED', () => {
      const result = classifier.classify('Card: 4111-1111-1111-1111');
      expect(result.classification).toBe('RESTRICTED');
      expect(result.detected.some(d => d.type === 'credit_card')).toBe(true);
    });

    it('detects private key as RESTRICTED', () => {
      const result = classifier.classify('-----BEGIN RSA PRIVATE KEY-----\nMIIEpAI...');
      expect(result.classification).toBe('RESTRICTED');
      expect(result.detected[0].type).toBe('private_key');
    });

    it('detects email as SENSITIVE', () => {
      const result = classifier.classify('Contact alice@example.com for details');
      expect(result.classification).toBe('SENSITIVE');
      expect(result.detected[0].type).toBe('email');
    });

    it('detects connection strings as SENSITIVE', () => {
      const result = classifier.classify('postgres://admin:pass@db.local:5432/prod');
      expect(result.classification).toBe('SENSITIVE');
      expect(result.detected.some(d => d.type === 'credential')).toBe(true);
    });

    it('detects file paths as INTERNAL', () => {
      const result = classifier.classify('Saved to /Users/alice/Documents/report.pdf');
      expect(result.classification).toBe('INTERNAL');
      expect(result.detected[0].type).toBe('file_path');
    });

    it('highest severity wins when multiple patterns match', () => {
      const result = classifier.classify(
        'User alice@example.com has SSN 123-45-6789'
      );
      expect(result.classification).toBe('RESTRICTED');
      expect(result.detected.length).toBeGreaterThan(1);
    });

    it('accepts custom patterns', () => {
      const custom = new Classifier([
        {
          name: 'employee_id',
          type: 'employee_id',
          pattern: /\bEMP-\d{6}\b/g,
          classification: 'SENSITIVE',
          confidence: 0.9,
        },
      ]);
      const result = custom.classify('Assigned to EMP-004521');
      expect(result.classification).toBe('SENSITIVE');
      expect(result.detected[0].type).toBe('employee_id');
    });
  });

  describe('redact', () => {
    it('replaces detected entities with placeholders', () => {
      const result = classifier.classify('Email alice@example.com, SSN 123-45-6789');
      const redacted = classifier.redact('Email alice@example.com, SSN 123-45-6789', result.detected);
      expect(redacted).toContain('[EMAIL]');
      expect(redacted).toContain('[SSN]');
      expect(redacted).not.toContain('alice@example.com');
      expect(redacted).not.toContain('123-45-6789');
    });

    it('returns original string when nothing detected', () => {
      const result = classifier.redact('Hello world', []);
      expect(result).toBe('Hello world');
    });
  });
});
