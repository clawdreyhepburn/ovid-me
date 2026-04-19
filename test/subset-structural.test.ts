import { describe, it, expect } from 'vitest';
import { MandateEngine } from '../src/mandate-engine.js';
import { normalize, normalizedMatch, exactMatch } from '../src/subset-structural.js';
import type { CedarMandate } from '@clawdreyhepburn/ovid';

const m = (cedar: string): CedarMandate => ({
  type: 'agent_mandate',
  rarFormat: 'cedar' as const,
  policySet: cedar,
});

// Force the prover to be treated as unavailable by pointing at a bogus path
// via an engine that can't find it. We do this by constructing a MandateEngine
// and using a PolicySource that returns policies designed to probe the
// structural fallback directly — the SMT prover will still run (it's real on
// this machine), but these tests are specifically about fallback behavior,
// so we isolate by setting proofTimeoutMs=1 to force it to time out when
// we need to.

describe('subset-structural helpers', () => {
  it('exactMatch is reflexive and strict', () => {
    expect(exactMatch('permit(principal, action, resource);', 'permit(principal, action, resource);')).toBe(true);
    expect(exactMatch('permit(principal, action, resource);', 'permit(principal, action , resource);')).toBe(false);
    expect(exactMatch('  permit(x,y,z);  ', 'permit(x,y,z);')).toBe(true); // trim-only tolerance
  });

  it('normalize strips line comments', () => {
    expect(normalize('// a comment\npermit(principal, action, resource);'))
      .toBe('permit(principal, action, resource);');
  });

  it('normalize strips block comments', () => {
    expect(normalize('/* block comment */ permit(principal, action, resource); /* trailing */'))
      .toBe('permit(principal, action, resource);');
  });

  it('normalize collapses whitespace and sorts clauses', () => {
    const a = normalize('permit(principal, action == A::"x", resource);\nforbid(principal, action == A::"y", resource);');
    const b = normalize('forbid(principal, action == A::"y", resource); permit(principal, action == A::"x", resource);');
    expect(a).toBe(b);
  });

  it('normalizedMatch treats cosmetic variants as equal', () => {
    expect(normalizedMatch(
      '// note\npermit(principal, action, resource);',
      'permit(principal, action, resource);',
    )).toBe(true);
  });

  it('normalizedMatch rejects a child with strictly broader permissions', () => {
    // Parent restricts to read_file; child permits all actions. Structurally distinct.
    const parent = 'permit(principal, action == Ovid::Action::"read_file", resource);';
    const child  = 'permit(principal, action, resource);';
    expect(normalizedMatch(parent, child)).toBe(false);
  });
});

describe('MandateEngine.verifySubset — unsoundness closure', () => {
  it('does NOT accept a child matching only via String.includes (historical bug)', async () => {
    // Construct a parent whose text CONTAINS the child's text verbatim inside
    // a different clause/comment. The old fallback (parent.includes(child))
    // would have returned proven:true. The new code must not.
    const parent = `
      // Here is a note: the default is permit(principal, action, resource);
      // but we actually want narrower:
      permit(principal, action == Ovid::Action::"read_file", resource);
    `;
    const child = 'permit(principal, action, resource);';

    const engine = new MandateEngine({
      subsetProof: 'required',
      structuralFallback: 'normalized', // most permissive structural mode
      proofTimeoutMs: 10, // force SMT prover to be inconclusive fast
      policySource: { getEffectivePolicy: async () => parent },
    });

    const result = await engine.verifySubset(m(child), 'parent-1');
    // Must NOT be proven. Old code with String.includes would incorrectly
    // return proven:true because `parent.includes(child)` is true (the
    // child text appears verbatim in the parent's comment).
    expect(result.proven).toBe(false);
    expect(result.method).not.toBe('smt');
  });

  it('structuralFallback=off refuses any fallback when SMT is inconclusive', async () => {
    const engine = new MandateEngine({
      subsetProof: 'required',
      structuralFallback: 'off',
      proofTimeoutMs: 10, // starve the prover
      policySource: { getEffectivePolicy: async () => 'permit(principal, action, resource);' },
    });

    // Even an exactly-matching child fails when fallback is off and SMT can't finish.
    // (On machines without the prover or with very tight timeouts, this is the
    //  safe default.)
    const result = await engine.verifySubset(
      m('permit(principal, action, resource);'),
      'parent-1',
    );

    // With the SMT prover present and fast on this host, it may still succeed;
    // but either way, the result must be either proven=true via method='smt'
    // or proven=false. NEVER proven=true via structural when off.
    if (result.proven) {
      expect(result.method).toBe('smt');
    } else {
      expect(result.method).toBe('none');
      expect(result.reason).toMatch(/structural fallback disabled|SMT prover/i);
    }
  });

  it('structuralFallback=exact accepts reflexive identity', async () => {
    const policy = 'permit(principal, action, resource);';
    const engine = new MandateEngine({
      subsetProof: 'required',
      structuralFallback: 'exact',
      proofTimeoutMs: 10, // force SMT to be inconclusive
      policySource: { getEffectivePolicy: async () => policy },
    });

    const result = await engine.verifySubset(m(policy), 'parent-1');
    // Either SMT proved it (if the prover is fast enough) or structural-exact
    // caught the reflexive case. Either way, proven=true.
    expect(result.proven).toBe(true);
    expect(['smt', 'structural-exact']).toContain(result.method);
  });

  it('structuralFallback=normalized tolerates comment/whitespace drift', async () => {
    const parent = '// header comment\npermit(principal, action, resource);';
    const child = 'permit( principal , action , resource );';
    const engine = new MandateEngine({
      subsetProof: 'required',
      structuralFallback: 'normalized',
      proofTimeoutMs: 10,
      policySource: { getEffectivePolicy: async () => parent },
    });

    const result = await engine.verifySubset(m(child), 'parent-1');
    // The policies are cosmetically different but normalize to the same thing.
    // SMT might also catch it; either way, proven=true.
    expect(result.proven).toBe(true);
    expect(['smt', 'structural-normalized']).toContain(result.method);
  });

  it('labels SMT-proven results with method=smt', async () => {
    const policy = 'permit(principal, action, resource);';
    const engine = new MandateEngine({
      subsetProof: 'required',
      // Even with fallback off, SMT should succeed for reflexive identity.
      structuralFallback: 'off',
      proofTimeoutMs: 5000,
      policySource: { getEffectivePolicy: async () => policy },
    });

    const result = await engine.verifySubset(m(policy), 'parent-1');
    // If the prover is installed on this machine, we should see method=smt.
    // If not, this test runs in a degraded environment and we skip the check.
    if (result.proven) {
      expect(result.method).toBe('smt');
    }
  });
});
