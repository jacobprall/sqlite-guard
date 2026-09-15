import { describe, it, expect } from 'vitest';
import { Guard } from '../src/guard.js';

describe('Guard (integration)', () => {
  function createGuard() {
    return new Guard({
      policy: {
        name: 'test',
        rules: [
          { classification: 'RESTRICTED', action: 'block', log: true },
          { classification: 'SENSITIVE', destinations: ['cloud_llm'], action: 'redact', log: true },
          { classification: 'INTERNAL', action: 'allow', log: true },
        ],
        default_action: 'allow',
        default_log: true,
      },
    });
  }

  it('classify returns classification result', () => {
    const guard = createGuard();
    const result = guard.classify('SSN 123-45-6789');
    expect(result.classification).toBe('RESTRICTED');
    guard.close();
  });

  it('check records audit entry and returns decision', () => {
    const guard = createGuard();

    const decision = guard.check('Hello world', {
      destination: 'cloud_llm',
      agent_id: 'test-agent',
    });
    expect(decision.action).toBe('allow');

    const entries = guard.queryAudit({ agent_id: 'test-agent' });
    expect(entries).toHaveLength(1);
    expect(entries[0].decision).toBe('allow');
    expect(entries[0].destination).toBe('cloud_llm');

    guard.close();
  });

  it('guarded() executes callback when allowed', () => {
    const guard = createGuard();

    const { result, decision } = guard.guarded(
      'What is 2+2?',
      { destination: 'cloud_llm' },
      (content) => `answer: ${content}`
    );

    expect(decision.action).toBe('allow');
    expect(result).toBe('answer: What is 2+2?');
    guard.close();
  });

  it('guarded() blocks and returns null for restricted content', () => {
    const guard = createGuard();

    const { result, decision } = guard.guarded(
      'Lookup SSN 123-45-6789',
      { destination: 'cloud_llm' },
      () => 'should not run'
    );

    expect(decision.action).toBe('block');
    expect(result).toBeNull();
    guard.close();
  });

  it('guarded() passes redacted content to callback', () => {
    const guard = createGuard();

    const { result, decision } = guard.guarded(
      'Email alice@example.com about it',
      { destination: 'cloud_llm' },
      (content) => content
    );

    expect(decision.action).toBe('redact');
    expect(result).toContain('[EMAIL]');
    expect(result).not.toContain('alice@example.com');
    guard.close();
  });

  it('audit summary aggregates correctly', () => {
    const guard = createGuard();

    guard.check('Hello', { destination: 'cloud_llm' });
    guard.check('Email alice@example.com', { destination: 'cloud_llm' });
    guard.check('SSN 123-45-6789', { destination: 'cloud_llm' });
    guard.check('Hi again', { destination: 'mcp_tool' });

    const summary = guard.summarizeAudit();
    expect(summary.total).toBe(4);
    expect(summary.blocked_count).toBe(1);
    expect(summary.redacted_count).toBe(1);

    guard.close();
  });

  it('updatePolicy changes active policy at runtime', () => {
    const guard = createGuard();

    // Initially: public content is allowed
    let decision = guard.check('Hello', { destination: 'cloud_llm' });
    expect(decision.action).toBe('allow');

    // Switch to strict: block everything
    guard.updatePolicy({
      name: 'lockdown',
      rules: [],
      default_action: 'block',
      default_log: true,
    });

    decision = guard.check('Hello', { destination: 'cloud_llm' });
    expect(decision.action).toBe('block');

    guard.close();
  });

  it('persists audit to disk when db_path is set', () => {
    const path = `/tmp/sqlite-guard-test-${Date.now()}.db`;
    const guard = new Guard({
      db_path: path,
      policy: {
        name: 'test',
        rules: [],
        default_action: 'allow',
        default_log: true,
      },
    });

    guard.check('test content', { destination: 'cloud_llm' });
    guard.close();

    // Reopen and verify persistence
    const guard2 = new Guard({
      db_path: path,
      policy: {
        name: 'test',
        rules: [],
        default_action: 'allow',
        default_log: true,
      },
    });

    const entries = guard2.queryAudit();
    expect(entries).toHaveLength(1);
    guard2.close();
  });
});
