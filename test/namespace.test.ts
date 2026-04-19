/**
 * Regression tests for finding #6: fail-open parser.
 *
 * Before the fix, a policy like:
 *   permit(principal, action == Jans::Action::"exec_command", resource);
 * was parsed with actions=null (because the parser only recognized
 * Ovid::Action::"..." literals), and policyMatchesRequest treated null
 * as "wildcard matches every action" -- turning a narrow Jans permit
 * into a wide-open allow-everything rule.
 *
 * After the fix:
 *   - Namespaces are recognized generically (<Namespace>::Action::"...").
 *   - Action names are extracted regardless of namespace.
 *   - Malformed action clauses raise an explicit parse error rather than
 *     silently falling through to wildcard.
 */

import { describe, it, expect } from 'vitest';
import { evaluateMandate, evaluateMandateAsync, parsePolicies, UnsupportedCedarSyntaxError } from '../src/evaluate.js';
import { isWasmAvailable } from '../src/cedar-engine-wasm.js';

describe('namespace-agnostic action parsing (finding #6 regression)', () => {
  it('parses action == Jans::Action::"X" as "X" in namespace Jans', () => {
    const policies = parsePolicies(
      'permit(principal, action == Jans::Action::"exec_command", resource);',
    );
    expect(policies).toHaveLength(1);
    expect(policies[0].actions).toEqual(['exec_command']);
  });

  it('parses action in [Jans::Action::"a", Ovid::Action::"b"] generically', () => {
    const policies = parsePolicies(
      'permit(principal, action in [Jans::Action::"exec_command", Ovid::Action::"read_file"], resource);',
    );
    expect(policies).toHaveLength(1);
    expect(policies[0].actions).toEqual(['exec_command', 'read_file']);
  });

  it('denies a request not in a Jans:: action list', () => {
    const cedar = 'permit(principal, action == Jans::Action::"exec_command", resource);';
    const result = evaluateMandate(cedar, { action: 'rm_rf', resource: '/etc' });
    expect(result.decision).toBe('deny');
  });

  it('CRITICAL: Jans::Action policy does NOT match every action (old bug)', () => {
    // This was the actual bypass: a narrow Jans permit became a wildcard
    // permit because the parser left actions=null when it didn't find an
    // Ovid:: literal.
    const cedar = 'permit(principal, action == Jans::Action::"exec_command", resource);';

    // Request a DIFFERENT action than the policy permits.
    const result = evaluateMandate(cedar, { action: 'delete_everything', resource: '/' });

    // Must be deny. Old code returned allow because actions=null was wildcard.
    expect(result.decision).toBe('deny');
  });

  it('allows a matching Jans:: request', () => {
    const cedar = 'permit(principal, action == Jans::Action::"exec_command", resource);';
    const result = evaluateMandate(cedar, { action: 'exec_command', resource: '/bin/ls' });
    expect(result.decision).toBe('allow');
  });

  it('rejects malformed action == RHS in strict mode', () => {
    // action == something that isn't <Namespace>::Action::"X"
    expect(() =>
      parsePolicies('permit(principal, action == "just_a_string", resource);'),
    ).toThrow(UnsupportedCedarSyntaxError);
  });

  it('rejects malformed action in [...] in strict mode', () => {
    // action in [] but with nothing namespace-shaped inside
    expect(() =>
      parsePolicies('permit(principal, action in ["x", "y"], resource);'),
    ).toThrow(UnsupportedCedarSyntaxError);
  });

  it('non-strict mode treats malformed action clauses as deny-all instead of wildcard', () => {
    const policies = parsePolicies(
      'permit(principal, action == "just_a_string", resource);',
      { strict: false },
    );
    // Parse succeeds (non-strict), but actions=[] means no action matches.
    expect(policies).toHaveLength(1);
    expect(policies[0].actions).toEqual([]);

    const result = evaluateMandate(
      'permit(principal, action == "just_a_string", resource);',
      { action: 'anything', resource: 'whatever' },
    );
    // Non-strict mode skips the unsupported feature entirely (strict default
    // applies in evaluateMandate). This test mostly documents that even in
    // the worst case, we don't fail open to wildcard.
    expect(result.decision).toBe('deny');
  });

  it('still allows bare wildcard action (no action clause at all)', () => {
    const cedar = 'permit(principal, action, resource);';
    const result = evaluateMandate(cedar, { action: 'anything', resource: '/x' });
    expect(result.decision).toBe('allow');
  });

  // NOTE: We intentionally do NOT add a WASM end-to-end Jans:: test here.
  // The WASM path currently returns null on all inputs (see finding #11 —
  // Cedarling schema format appears to be rejected by the pinned Cedarling
  // version). The WASM namespace fix is still correct — it makes WASM
  // namespace-agnostic for when the path is repaired — but there is no
  // point asserting end-to-end Jans:: allow/deny until WASM itself works.
  // The fallback parser IS exercised here and is what matters for any
  // Carapace→OVID-ME pipeline right now (engine='fallback' or 'auto' when
  // WASM is unavailable).

  it('tracks all namespaces seen in a mixed policy', () => {
    const policies = parsePolicies(
      'permit(principal, action in [Jans::Action::"a", Ovid::Action::"b", Jans::Action::"c"], resource);',
    );
    expect(policies[0].actionNamespaces.sort()).toEqual(['Jans', 'Ovid']);
  });
});
