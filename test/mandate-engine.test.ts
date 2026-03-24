import { describe, it, expect } from 'vitest';
import { MandateEngine } from '../src/mandate-engine.js';
import type { CedarMandate } from '@clawdreyhepburn/ovid';

const makeMandate = (cedar: string): CedarMandate => ({ type: 'agent_mandate', rarFormat: 'cedar' as const, policySet: cedar });

describe('MandateEngine', () => {
  it('enforce mode — deny', async () => {
    const engine = new MandateEngine({ mandateMode: 'enforce' });
    const result = await engine.evaluate('jti-1', makeMandate(''), { action: 'exec', resource: 'ls' });
    expect(result.decision).toBe('deny');
    expect(result.mode).toBe('enforce');
  });

  it('enforce mode — allow', async () => {
    const engine = new MandateEngine({ mandateMode: 'enforce' });
    const mandate = makeMandate('permit(principal, action == Ovid::Action::"read_file", resource);');
    const result = await engine.evaluate('jti-2', mandate, { action: 'read_file', resource: '/foo' });
    expect(result.decision).toBe('allow');
  });

  it('dry-run mode returns allow even on deny', async () => {
    const engine = new MandateEngine({ mandateMode: 'dry-run' });
    const result = await engine.evaluate('jti-3', makeMandate(''), { action: 'exec', resource: 'rm' });
    expect(result.decision).toBe('allow');
    expect(result.mode).toBe('dry-run');
    expect(result.reason).toContain('dry-run');
  });

  it('shadow mode evaluates both mandates', async () => {
    const engine = new MandateEngine({
      mandateMode: 'shadow',
      shadowMandate: makeMandate('permit(principal, action, resource);'),
    });
    // Real mandate denies (empty), shadow permits
    const result = await engine.evaluate('jti-4', makeMandate(''), { action: 'exec', resource: 'ls' });
    expect(result.decision).toBe('deny'); // real decision
    expect(result.shadowDecision).toBe('allow');
    expect(result.mode).toBe('shadow');
  });

  it('shadow mode without shadow mandate', async () => {
    const engine = new MandateEngine({ mandateMode: 'shadow' });
    const result = await engine.evaluate('jti-5', makeMandate('permit(principal, action, resource);'), { action: 'x', resource: 'y' });
    expect(result.decision).toBe('allow');
    expect(result.shadowDecision).toBeUndefined();
  });

  it('subset proof off — always proven', async () => {
    const engine = new MandateEngine({ subsetProof: 'off' });
    const result = await engine.verifySubset(makeMandate('permit(principal, action, resource);'), 'parent-1');
    expect(result.proven).toBe(true);
  });

  it('subset proof required — no policy source', async () => {
    const engine = new MandateEngine({ subsetProof: 'required', policySource: null });
    const result = await engine.verifySubset(makeMandate('permit(principal, action, resource);'), 'parent-1');
    expect(result.proven).toBe(false);
    expect(result.reason).toContain('no policy source');
  });

  it('subset proof with policy source — exact match proven', async () => {
    const policy = 'permit(principal, action, resource);';
    const engine = new MandateEngine({
      subsetProof: 'required',
      policySource: { getEffectivePolicy: async () => policy },
    });
    const result = await engine.verifySubset(makeMandate(policy), 'parent-1');
    expect(result.proven).toBe(true);
  });

  it('subset proof with policy source — no match', async () => {
    const engine = new MandateEngine({
      subsetProof: 'required',
      policySource: { getEffectivePolicy: async () => 'forbid(principal, action, resource);' },
    });
    const result = await engine.verifySubset(
      makeMandate('permit(principal, action, resource);'),
      'parent-1',
    );
    expect(result.proven).toBe(false);
    expect(result.reason).toContain('inconclusive');
  });
});
