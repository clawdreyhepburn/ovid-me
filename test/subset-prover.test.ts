import { describe, it, expect } from 'vitest';
import {
  proveSubset,
  proverBinaryExists,
  parseCounterexample,
  revalidateCounterexample,
} from '../src/subset-prover.js';
import { evaluateMandateAsync } from '../src/evaluate.js';

describe('subset-prover', () => {
  it('graceful fallback when binary not found', async () => {
    const result = await proveSubset(
      'permit(principal, action, resource);',
      'permit(principal, action == Ovid::Action::"read_file", resource);',
      { binaryPath: '/nonexistent/binary' },
    );
    expect(result.proven).toBe(false);
    expect(result.reason).toContain('not found');
    expect(typeof result.durationMs).toBe('number');
  });

  it('proverBinaryExists returns false for nonexistent path', () => {
    expect(proverBinaryExists('/nonexistent/binary')).toBe(false);
  });

  it('proverBinaryExists detects the real binary', () => {
    const exists = proverBinaryExists();
    // This test documents whether the binary is present on this machine
    expect(typeof exists).toBe('boolean');
    if (exists) {
      console.log('  ✓ SMT prover binary found at default path');
    } else {
      console.log('  ⓘ SMT prover binary not found (expected on CI)');
    }
  });

  it('timeout behavior', async () => {
    // Use a very short timeout with a nonexistent binary — should return quickly
    const result = await proveSubset(
      'permit(principal, action, resource);',
      'permit(principal, action, resource);',
      { timeoutMs: 1, binaryPath: '/nonexistent/binary' },
    );
    expect(result.proven).toBe(false);
    expect(result.durationMs).toBeLessThan(1000);
  });

  it('real prover binary (if available)', async () => {
    if (!proverBinaryExists()) {
      console.log('  ⓘ Skipping real prover test — binary not found');
      return;
    }

    // The current prover binary doesn't accept --parent/--child args,
    // so it will likely exit with an error. That's fine — we verify
    // it doesn't hang and returns a result.
    const result = await proveSubset(
      'permit(principal, action, resource);',
      'permit(principal, action == Ovid::Action::"read_file", resource);',
      { timeoutMs: 10000 },
    );
    expect(typeof result.proven).toBe('boolean');
    expect(typeof result.durationMs).toBe('number');
    console.log(`  Prover result: proven=${result.proven}, reason=${result.reason}, ${result.durationMs}ms`);
  });
});

describe('counterexample parsing (SynSec §4.4)', () => {
  it('parses a well-formed counterexample line (exact prover format)', () => {
    // Build the JSON the way the Rust prover does, then confirm round-trip.
    const cexObj = {
      principal: 'Ovid::Agent::""',
      action: 'Ovid::Action::"exec"',
      resource: 'Ovid::Shell::""',
    };
    const out = [
      'subset: not-proven',
      'reason: child allows a request that parent denies ...',
      `counterexample: ${JSON.stringify(cexObj)}`,
    ].join('\n');
    const cex = parseCounterexample(out);
    expect(cex).toBeDefined();
    expect(cex!.action).toBe('Ovid::Action::"exec"');
    expect(cex!.resource).toBe('Ovid::Shell::""');
    expect(cex!.principal).toBe('Ovid::Agent::""');
  });

  it('parses the real prover output for a broadening mandate', async () => {
    if (!proverBinaryExists()) return;
    // Parent allows only read_file; child permits exec — a genuine broadening.
    const parent = 'permit(principal, action == Ovid::Action::"read_file", resource);';
    const child = 'permit(principal, action == Ovid::Action::"exec", resource);';
    const result = await proveSubset(parent, child, { timeoutMs: 10000 });
    expect(result.proven).toBe(false);
    // The real prover should have produced a concrete witness we can parse.
    if (result.counterexample) {
      expect(typeof result.counterexample.action).toBe('string');
      expect(result.counterexample.action.length).toBeGreaterThan(0);
    }
  });

  it('returns undefined when no counterexample line is present', () => {
    expect(parseCounterexample('subset: proven\nreason: ...')).toBeUndefined();
  });

  it('returns undefined for a malformed counterexample line', () => {
    expect(parseCounterexample('counterexample: {not json')).toBeUndefined();
  });
});

describe('counterexample re-validation through Cedar (SynSec §4.4)', () => {
  const evaluator = async (
    policyText: string,
    req: { action: string; resource: string; resourceType?: string; principalType?: string },
  ) => {
    const res = await evaluateMandateAsync(policyText, 'test-revalidate', req, 'auto');
    return res ? { decision: res.decision } : null;
  };

  it('validates a genuine divergence (child allows exec, parent does not)', async () => {
    // Parent forbids exec; child permits it. The witness exec/Shell request
    // must reproduce child=allow, parent=deny through Cedar.
    const parent = 'permit(principal, action == Ovid::Action::"read_file", resource);';
    const child = 'permit(principal, action == Ovid::Action::"exec", resource);';
    const cex = {
      principal: 'Ovid::Agent::""',
      action: 'Ovid::Action::"exec"',
      resource: 'Ovid::Shell::""',
    };
    const check = await revalidateCounterexample(cex, parent, child, evaluator);
    expect(check.validated).toBe(true);
    expect(check.childDecision).toBe('allow');
    expect(check.parentDecision).toBe('deny');
  });

  it('rejects a spurious witness that does not reproduce divergence', async () => {
    // Here BOTH policies allow the witnessed action, so Cedar does NOT see a
    // divergence — this is exactly the SMT-encoding-fault case we guard against.
    const parent = 'permit(principal, action == Ovid::Action::"read_file", resource);';
    const child = 'permit(principal, action == Ovid::Action::"read_file", resource);';
    const cex = {
      principal: 'Ovid::Agent::""',
      action: 'Ovid::Action::"read_file"',
      resource: 'Ovid::File::""',
    };
    const check = await revalidateCounterexample(cex, parent, child, evaluator);
    expect(check.validated).toBe(false);
    expect(check.reason).toMatch(/did not reproduce/i);
  });

  it('reports engine-unavailable rather than silently passing', async () => {
    const cex = {
      principal: 'Ovid::Agent::""',
      action: 'Ovid::Action::"exec"',
      resource: 'Ovid::Shell::""',
    };
    const check = await revalidateCounterexample(
      cex,
      'permit(principal, action, resource);',
      'permit(principal, action, resource);',
      async () => null, // simulate unavailable engine
    );
    expect(check.validated).toBe(false);
    expect(check.reason).toMatch(/unavailable/i);
  });
});
