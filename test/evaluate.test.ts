import { describe, it, expect } from 'vitest';
import { evaluateMandate, parsePolicies, UnsupportedCedarSyntaxError } from '../src/evaluate.js';

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

describe('strict parsing — unsupported Cedar syntax', () => {
  it('rejects unless clauses in strict mode', () => {
    const cedar = `permit(principal, action == Ovid::Action::"read_file", resource) unless { resource.path like "/secret/*" };`;
    expect(() => parsePolicies(cedar)).toThrow(UnsupportedCedarSyntaxError);
    const result = evaluateMandate(cedar, { action: 'read_file', resource: '/foo' });
    expect(result.decision).toBe('deny');
    expect(result.reason).toContain('unsupported Cedar syntax');
    expect(result.reason).toContain('unless');
  });

  it('rejects principal == constraints in strict mode', () => {
    const cedar = `permit(principal == Ovid::Agent::"admin", action == Ovid::Action::"exec", resource);`;
    expect(() => parsePolicies(cedar)).toThrow(UnsupportedCedarSyntaxError);
    const result = evaluateMandate(cedar, { action: 'exec', resource: '/foo' });
    expect(result.decision).toBe('deny');
    expect(result.reason).toContain('principal_equality');
  });

  it('rejects resource == constraints in strict mode', () => {
    const cedar = `permit(principal, action == Ovid::Action::"read_file", resource == Ovid::Resource::"config");`;
    expect(() => parsePolicies(cedar)).toThrow(UnsupportedCedarSyntaxError);
  });

  it('rejects has operator in strict mode', () => {
    const cedar = `permit(principal, action, resource) when { resource has path };`;
    expect(() => parsePolicies(cedar)).toThrow(UnsupportedCedarSyntaxError);
  });

  it('rejects .contains() in strict mode', () => {
    const cedar = `permit(principal, action, resource) when { resource.tags.contains("safe") };`;
    expect(() => parsePolicies(cedar)).toThrow(UnsupportedCedarSyntaxError);
  });

  it('rejects context conditions in strict mode', () => {
    const cedar = `permit(principal, action, resource) when { context.time > 9 };`;
    expect(() => parsePolicies(cedar)).toThrow(UnsupportedCedarSyntaxError);
    const result = evaluateMandate(cedar, { action: 'read_file', resource: '/foo' });
    expect(result.decision).toBe('deny');
    expect(result.reason).toContain('context_conditions');
  });

  it('rejects boolean combinators in when clause', () => {
    const cedar = `permit(principal, action, resource) when { resource.path like "/src/*" && resource.path like "/test/*" };`;
    expect(() => parsePolicies(cedar)).toThrow(UnsupportedCedarSyntaxError);
  });

  it('strict: false allows unsupported syntax (skips with warning)', () => {
    const cedar = `
      permit(principal, action == Ovid::Action::"read_file", resource) unless { resource.path like "/secret/*" };
      permit(principal, action == Ovid::Action::"write_file", resource);
    `;
    // Non-strict: should not throw, but skips the unsupported policy
    const policies = parsePolicies(cedar, { strict: false });
    expect(policies).toHaveLength(1);
    expect(policies[0].actions).toEqual(['write_file']);
  });

  it('supported syntax still works in strict mode', () => {
    const cedar = `
      permit(principal, action == Ovid::Action::"read_file", resource);
      permit(principal, action, resource) when { resource.path like "/src/*" };
      forbid(principal, action == Ovid::Action::"exec", resource);
    `;
    const policies = parsePolicies(cedar);
    expect(policies).toHaveLength(3);
  });
});
