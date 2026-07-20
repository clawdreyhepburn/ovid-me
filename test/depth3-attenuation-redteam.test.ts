import { describe, it, expect } from 'vitest';
import { MandateEngine } from '../src/mandate-engine.js';
import { proverBinaryExists } from '../src/subset-prover.js';
import type { CedarMandate } from '@clawdreyhepburn/ovid';

const makeMandate = (cedar: string): CedarMandate => ({
  type: 'agent_mandate',
  rarFormat: 'cedar' as const,
  policySet: cedar,
});

/**
 * Depth-3+ chain attenuation red-team gate (SCOPE.md / FIX-DESIGN.md §5b).
 *
 * The soundness property under test: a grandchild's subset proof MUST be
 * checked against its IMMEDIATE PARENT's mandate, not root's allow-all. A
 * grandchild whose mandate EXCEEDS its parent's read-only grant must NOT
 * prove; a grandchild that stays within it must prove via the SMT engine.
 *
 * Here the parent principal "p2" (a depth-2 read-only sub-agent) resolves to
 * a read/search-only effective policy. This is exactly what getEffectivePolicy
 * returns once Break 1 is fixed and the grandchild's `iss` reflects the real
 * parent instead of always resolving to root's allow-all.
 */
describe('depth-3 subset soundness (red-team gate)', () => {
  const PARENT_READONLY =
    'permit(principal, action in [Ovid::Action::"read", Ovid::Action::"search"], resource);';

  const engineFor = () =>
    new MandateEngine({
      subsetProof: 'required',
      structuralFallback: 'off', // force the SMT engine; no reflexive masking
      policySource: {
        getEffectivePolicy: async (p: string) =>
          p === 'p2' ? PARENT_READONLY : null,
      },
    });

  it('RED TEAM: grandchild wanting write/exec under a read-only parent must NOT prove', async () => {
    const engine = engineFor();
    const overScoped = makeMandate(
      'permit(principal, action in [Ovid::Action::"read", Ovid::Action::"write", Ovid::Action::"exec"], resource);',
    );
    const result = await engine.verifySubset(overScoped, 'p2');
    expect(result.proven).toBe(false);
  });

  it('CONTROL: grandchild wanting read-only (subset of parent) must prove via SMT', async () => {
    // Strict subset (not reflexive) requires the SMT prover. Skip on hosts
    // without agent-authz-prover / cvc5 (e.g. default GitHub Actions runners).
    if (!proverBinaryExists()) {
      console.info('Skipping SMT CONTROL — prover binary not found');
      return;
    }
    const engine = engineFor();
    const inBounds = makeMandate(
      'permit(principal, action in [Ovid::Action::"read"], resource);',
    );
    const result = await engine.verifySubset(inBounds, 'p2');
    expect(result.proven).toBe(true);
    expect(result.method).toBe('smt');
  });

  it('SANITY: an unknown parent principal has no effective policy → not proven, fail-closed', async () => {
    const engine = engineFor();
    const anything = makeMandate('permit(principal, action, resource);');
    const result = await engine.verifySubset(anything, 'unknown-grandparent');
    expect(result.proven).toBe(false);
    expect(result.reason).toContain('no effective policy');
  });
});
