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

  it('WASM engine evaluates Jans:: policies correctly (finding #9 bridge)', async () => {
    // Skip if WASM isn't available on this host.
    if (!(await isWasmAvailable())) return;

    const policy = 'permit(principal, action == Jans::Action::"exec_command", resource);';

    // Matching action through WASM.
    const allowResult = await evaluateMandateAsync(policy, 'agent-1', {
      action: 'exec_command',
      resource: '/bin/ls',
    }, 'wasm');
    expect(allowResult.decision).toBe('allow');
    expect(allowResult.engine).toBe('wasm');

    // Non-matching action through WASM.
    const denyResult = await evaluateMandateAsync(policy, 'agent-1', {
      action: 'rm_rf',
      resource: '/',
    }, 'wasm');
    expect(denyResult.decision).toBe('deny');
    expect(denyResult.engine).toBe('wasm');
  });

  it('CRITICAL: accepts BARE Action::"X" (Carapace deployments use this form)', () => {
    // Real Carapace policies look like:
    //   forbid(principal, action == Action::"exec_command", resource == Shell::"rm");
    // The fallback parser MUST accept bare Action::"..." without a namespace
    // prefix. Before 2026-04-19 it only accepted <Namespace>::Action::"X"
    // and silently rejected bare Action as malformed, which caused real
    // Carapace policies to produce parse errors.
    const policies = parsePolicies(
      'forbid(principal, action == Action::"exec_command", resource);',
    );
    expect(policies).toHaveLength(1);
    expect(policies[0].effect).toBe('forbid');
    expect(policies[0].actions).toEqual(['exec_command']);
    expect(policies[0].actionNamespaces).toEqual(['']);
  });

  it('parses bare Action::"X" in an action list', () => {
    const policies = parsePolicies(
      'permit(principal, action in [Action::"read_file", Action::"write_file"], resource);',
    );
    expect(policies).toHaveLength(1);
    expect(policies[0].actions).toEqual(['read_file', 'write_file']);
    expect(policies[0].actionNamespaces).toEqual(['']);
  });

  it('mixes bare and namespaced Action entries', () => {
    const policies = parsePolicies(
      'permit(principal, action in [Action::"a", Jans::Action::"b"], resource);',
    );
    expect(policies).toHaveLength(1);
    expect(policies[0].actions).toEqual(['a', 'b']);
    expect(policies[0].actionNamespaces.sort()).toEqual(['', 'Jans']);
  });

  it('evaluates bare Action:: correctly (not wildcard)', () => {
    const cedar = 'forbid(principal, action == Action::"exec_command", resource);';
    // The forbid should apply only to exec_command, not every action.
    const exec = evaluateMandate(cedar, { action: 'exec_command', resource: '/x' });
    expect(exec.decision).toBe('deny');
    const other = evaluateMandate(cedar, { action: 'read_file', resource: '/x' });
    // No permit — default deny.
    expect(other.decision).toBe('deny');
  });

  it('WASM handles multi-statement Cedar text (Carapace layout)', async () => {
    if (!(await isWasmAvailable())) return;
    // Two statements concatenated (which is how CarapacePolicySource returns
    // the deployment policy). Cedarling's policy_content decoder expects
    // ONE statement per entry, so the engine splits on permit/forbid
    // boundaries before submitting.
    const cedar =
      'permit(principal, action, resource);\n' +
      'forbid(principal, action == Action::"exec_command", resource);';

    // forbid overrides permit: exec_command denied
    const denyResult = await evaluateMandateAsync(cedar, 'agent-1', {
      action: 'exec_command',
      resource: '/bin/ls',
    }, 'wasm');
    expect(denyResult.engine).toBe('wasm');
    expect(denyResult.decision).toBe('deny');

    // Other actions flow through the wildcard permit
    const allowResult = await evaluateMandateAsync(cedar, 'agent-1', {
      action: 'read_file',
      resource: '/foo',
    }, 'wasm');
    expect(allowResult.engine).toBe('wasm');
    expect(allowResult.decision).toBe('allow');
  });

  it('tracks all namespaces seen in a mixed policy', () => {
    const policies = parsePolicies(
      'permit(principal, action in [Jans::Action::"a", Ovid::Action::"b", Jans::Action::"c"], resource);',
    );
    expect(policies[0].actionNamespaces.sort()).toEqual(['Jans', 'Ovid']);
  });
});
