import { describe, it, expect } from 'vitest';
import { evaluateMandate, parsePolicies } from '../src/evaluate.js';

describe('evaluateMandate', () => {
  it('exact action match — permit', () => {
    const cedar = `permit(principal, action == Ovid::Action::"read_file", resource);`;
    const result = evaluateMandate(cedar, { action: 'read_file', resource: '/foo' });
    expect(result.decision).toBe('allow');
  });

  it('exact action match — no match', () => {
    const cedar = `permit(principal, action == Ovid::Action::"read_file", resource);`;
    const result = evaluateMandate(cedar, { action: 'exec', resource: '/foo' });
    expect(result.decision).toBe('deny');
  });

  it('action list — matches one', () => {
    const cedar = `permit(principal, action in [Ovid::Action::"read_file", Ovid::Action::"write_file"], resource);`;
    const result = evaluateMandate(cedar, { action: 'write_file', resource: '/foo' });
    expect(result.decision).toBe('allow');
  });

  it('action list — no match', () => {
    const cedar = `permit(principal, action in [Ovid::Action::"read_file", Ovid::Action::"write_file"], resource);`;
    const result = evaluateMandate(cedar, { action: 'exec', resource: '/foo' });
    expect(result.decision).toBe('deny');
  });

  it('resource glob — matches', () => {
    const cedar = `permit(principal, action, resource) when { resource.path like "/src/*" };`;
    const result = evaluateMandate(cedar, { action: 'read_file', resource: '/src/index.ts' });
    expect(result.decision).toBe('allow');
  });

  it('resource glob — no match', () => {
    const cedar = `permit(principal, action, resource) when { resource.path like "/src/*" };`;
    const result = evaluateMandate(cedar, { action: 'read_file', resource: '/etc/passwd' });
    expect(result.decision).toBe('deny');
  });

  it('forbid overrides permit', () => {
    const cedar = `
      permit(principal, action == Ovid::Action::"exec", resource);
      forbid(principal, action == Ovid::Action::"exec", resource);
    `;
    const result = evaluateMandate(cedar, { action: 'exec', resource: 'rm -rf /' });
    expect(result.decision).toBe('deny');
    expect(result.reason).toBe('explicit forbid');
  });

  it('forbid all denies everything', () => {
    const cedar = `forbid(principal, action, resource);`;
    const result = evaluateMandate(cedar, { action: 'read_file', resource: '/foo' });
    expect(result.decision).toBe('deny');
  });

  it('forbid specific action', () => {
    const cedar = `
      permit(principal, action, resource);
      forbid(principal, action == Ovid::Action::"exec", resource);
    `;
    expect(evaluateMandate(cedar, { action: 'read_file', resource: '/foo' }).decision).toBe('allow');
    expect(evaluateMandate(cedar, { action: 'exec', resource: 'ls' }).decision).toBe('deny');
  });

  it('empty policy — deny all', () => {
    const result = evaluateMandate('', { action: 'read_file', resource: '/foo' });
    expect(result.decision).toBe('deny');
    expect(result.reason).toBe('no policies defined');
  });

  it('multiple permits — first match wins', () => {
    const cedar = `
      permit(principal, action == Ovid::Action::"read_file", resource);
      permit(principal, action == Ovid::Action::"write_file", resource);
    `;
    expect(evaluateMandate(cedar, { action: 'read_file', resource: '/x' }).decision).toBe('allow');
    expect(evaluateMandate(cedar, { action: 'write_file', resource: '/x' }).decision).toBe('allow');
    expect(evaluateMandate(cedar, { action: 'exec', resource: '/x' }).decision).toBe('deny');
  });

  it('wildcard permit allows anything', () => {
    const cedar = `permit(principal, action, resource);`;
    expect(evaluateMandate(cedar, { action: 'anything', resource: 'whatever' }).decision).toBe('allow');
  });
});

describe('parsePolicies', () => {
  it('parses multiple policies', () => {
    const cedar = `
      permit(principal, action == Ovid::Action::"read_file", resource);
      forbid(principal, action == Ovid::Action::"exec", resource);
    `;
    const policies = parsePolicies(cedar);
    expect(policies).toHaveLength(2);
    expect(policies[0].effect).toBe('permit');
    expect(policies[1].effect).toBe('forbid');
  });
});
