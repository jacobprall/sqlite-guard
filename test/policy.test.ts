import { describe, it, expect } from 'vitest';
import { PolicyEngine } from '../src/policy/engine.js';
import { Classifier } from '../src/classify/classifier.js';
import type { PolicyDefinition } from '../src/types.js';

const TEST_POLICY: PolicyDefinition = {
  name: 'test',
  rules: [
    { classification: 'RESTRICTED', action: 'block', log: true },
    { classification: 'SENSITIVE', destinations: ['cloud_llm'], action: 'redact', log: true },
    { classification: 'SENSITIVE', destinations: ['mcp_tool'], action: 'allow', log: true },
    { classification: 'INTERNAL', action: 'allow', log: true },
  ],
  default_action: 'allow',
  default_log: true,
};

describe('PolicyEngine', () => {
  const classifier = new Classifier();
  const engine = new PolicyEngine(TEST_POLICY, classifier);

  it('allows public content to cloud LLM', () => {
    const decision = engine.evaluate('The revenue was strong in Q3.', 'cloud_llm');
    expect(decision.action).toBe('allow');
    expect(decision.classification).toBe('PUBLIC');
  });

  it('blocks restricted content regardless of destination', () => {
    const decision = engine.evaluate('SSN: 123-45-6789', 'cloud_llm');
    expect(decision.action).toBe('block');
    expect(decision.classification).toBe('RESTRICTED');
  });

  it('redacts sensitive content sent to cloud LLM', () => {
    const decision = engine.evaluate('Contact alice@example.com', 'cloud_llm');
    expect(decision.action).toBe('redact');
    expect(decision.classification).toBe('SENSITIVE');
    expect(decision.redacted_content).toContain('[EMAIL]');
    expect(decision.redacted_content).not.toContain('alice@example.com');
  });

  it('allows sensitive content sent to MCP tool', () => {
    const decision = engine.evaluate('Contact alice@example.com', 'mcp_tool');
    expect(decision.action).toBe('allow');
  });

  it('allows internal content', () => {
    const decision = engine.evaluate('File at /Users/alice/docs/report.pdf', 'cloud_llm');
    expect(decision.action).toBe('allow');
    expect(decision.classification).toBe('INTERNAL');
  });

  it('uses default action for unmatched combinations', () => {
    const strictPolicy: PolicyDefinition = {
      name: 'strict',
      rules: [],
      default_action: 'block',
      default_log: true,
    };
    const strictEngine = new PolicyEngine(strictPolicy, classifier);
    const decision = strictEngine.evaluate('Hello world', 'cloud_llm');
    expect(decision.action).toBe('block');
  });

  it('first matching rule wins', () => {
    const policy: PolicyDefinition = {
      name: 'ordered',
      rules: [
        { classification: 'SENSITIVE', destinations: ['cloud_llm'], action: 'block' },
        { classification: 'SENSITIVE', destinations: ['cloud_llm'], action: 'allow' },
      ],
      default_action: 'allow',
      default_log: true,
    };
    const eng = new PolicyEngine(policy, classifier);
    const decision = eng.evaluate('Contact alice@example.com', 'cloud_llm');
    expect(decision.action).toBe('block');
  });
});
