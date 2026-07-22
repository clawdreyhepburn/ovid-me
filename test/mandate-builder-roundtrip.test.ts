/**
 * Round-trip: @clawdreyhepburn/ovid buildMandate() output must be enforceable
 * by this package's fallback evaluator. Also pins the namespace-insensitive
 * resource-type match (Ovid::Shell vs bare Shell) so it can't regress.
 */
import { describe, it, expect } from 'vitest';
import { buildMandate } from '@clawdreyhepburn/ovid';
import { evaluateMandate, parsePolicies } from '../src/evaluate.js';

describe('mandate builder → evaluator round-trip', () => {
  it('shell allowlist + forbid enforces per-binary', () => {
    const m = buildMandate({
      allow: [{ action: 'exec', resource: { type: 'Shell', in: ['git', 'npm'] } }],
      forbid: [{ action: 'exec', resource: { type: 'Shell', in: ['rm'] } }],
    });
    const ev = (id: string) =>
      evaluateMandate(m.policySet, { action: 'exec', resource: id, resourceType: 'Shell' }).decision;
    expect(ev('git')).toBe('allow');
    expect(ev('npm')).toBe('allow');
    expect(ev('rm')).toBe('deny'); // forbid wins
    expect(ev('curl')).toBe('deny'); // not granted
  });

  it('file path glob enforces', () => {
    const m = buildMandate({
      allow: [{ action: 'read', resource: { type: 'File', pathLike: ['/src/*'] } }],
    });
    const ev = (p: string) =>
      evaluateMandate(m.policySet, { action: 'read', resource: p, resourceType: 'File', context: { path: p } }).decision;
    expect(ev('/src/main.ts')).toBe('allow');
    expect(ev('/etc/passwd')).toBe('deny');
  });

  it('web endpoint host allowlist enforces', () => {
    const m = buildMandate({
      allow: [{ action: 'fetch', resource: { type: 'API', in: ['api.github.com'] } }],
    });
    const ev = (h: string) =>
      evaluateMandate(m.policySet, { action: 'fetch', resource: h, resourceType: 'WebEndpoint' }).decision;
    expect(ev('api.github.com')).toBe('allow');
    expect(ev('evil.example.com')).toBe('deny');
  });

  it('default mandate allows read/search/summarize, denies exec', () => {
    const m = buildMandate();
    expect(evaluateMandate(m.policySet, { action: 'read', resource: 'x', resourceType: 'File' }).decision).toBe('allow');
    expect(evaluateMandate(m.policySet, { action: 'exec', resource: 'rm', resourceType: 'Shell' }).decision).toBe('deny');
  });
});

describe('namespace-insensitive resource-type match (regression)', () => {
  const NS_POLICY = 'forbid(principal, action == Ovid::Action::"exec", resource == Ovid::Shell::"rm");';

  it('parser preserves fully-qualified type', () => {
    const p = parsePolicies(NS_POLICY);
    expect(p[0].resourceEqualities).toEqual([{ type: 'Ovid::Shell', id: 'rm' }]);
  });

  it('fully-qualified policy type matches a bare request resourceType', () => {
    // Pre-fix this returned allow because "Ovid::Shell" !== "Shell".
    const r = evaluateMandate(
      `permit(principal, action == Ovid::Action::"exec", resource);\n${NS_POLICY}`,
      { action: 'exec', resource: 'rm', resourceType: 'Shell' },
    );
    expect(r.decision).toBe('deny');
  });

  it('mismatched kind still does not fire', () => {
    const r = evaluateMandate(
      `permit(principal, action == Ovid::Action::"exec", resource);\n${NS_POLICY}`,
      { action: 'exec', resource: 'rm', resourceType: 'Tool' },
    );
    expect(r.decision).toBe('allow');
  });
});
