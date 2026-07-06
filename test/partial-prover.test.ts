import { describe, it, expect } from 'vitest';
import {
  probePartial,
  probeOptions,
  partialProverExists,
  parsePartialOutput,
} from '../src/partial-prover.js';

const MANDATE = `
@id("read-workspace-files")
permit (
  principal,
  action == Ovid::Action::"read",
  resource is Ovid::File
) when { resource.path like "/Users/clawdreyhepburn/.openclaw/workspace/*" };

@id("exec-git-status")
permit (
  principal,
  action == Ovid::Action::"exec",
  resource is Ovid::Shell
) when { resource.command == "git status" };
`;

describe('partial-prover — graceful fallback', () => {
  it('returns null verdict when binary not found', async () => {
    const r = await probePartial(
      MANDATE,
      { action: 'Ovid::Action::"read"', resource: '?Ovid::File' },
      { binaryPath: '/nonexistent/binary' },
    );
    expect(r.verdict).toBeNull();
    expect(r.reason).toContain('not found');
    expect(typeof r.durationMs).toBe('number');
  });

  it('partialProverExists returns false for nonexistent path', () => {
    expect(partialProverExists('/nonexistent/binary')).toBe(false);
  });

  it('partialProverExists returns a boolean for the default path', () => {
    expect(typeof partialProverExists()).toBe('boolean');
  });

  it('respects a short timeout', async () => {
    const r = await probePartial(
      MANDATE,
      { action: 'Ovid::Action::"read"', resource: '?Ovid::File' },
      { timeoutMs: 1, binaryPath: '/nonexistent/binary' },
    );
    expect(r.verdict).toBeNull();
    expect(r.durationMs).toBeLessThan(1000);
  });
});

describe('parsePartialOutput — pure parser (always runs)', () => {
  it('parses Allow', () => {
    const out = 'partial: Allow\nreason: mandate permits this request for all substitutions of the unknowns';
    const r = parsePartialOutput(out, 0);
    expect(r.verdict).toBe('Allow');
    expect(r.residuals).toEqual([]);
    expect(r.unknowns).toEqual([]);
  });

  it('parses Deny', () => {
    const out = 'partial: Deny\nreason: mandate denies this request for all substitutions of the unknowns';
    const r = parsePartialOutput(out, 0);
    expect(r.verdict).toBe('Deny');
  });

  it('parses Depends with a residual and unknowns', () => {
    const out = [
      'partial: Depends',
      'reason: decision depends on unknown components; residual conditions follow',
      'residual: @id("read-workspace-files") permit( principal, action, resource ) when { ((unknown("resource")).path) like "/ws/*" };',
      'unknowns: Ovid::File::"x", Ovid::File::"y"',
    ].join('\n');
    const r = parsePartialOutput(out, 0);
    expect(r.verdict).toBe('Depends');
    expect(r.residuals).toHaveLength(1);
    expect(r.residuals[0]).toContain('like "/ws/*"');
    expect(r.unknowns).toEqual(['Ovid::File::"x"', 'Ovid::File::"y"']);
  });

  it('drops a "(none non-trivial)" residual placeholder', () => {
    const out = 'partial: Depends\nresidual: (none non-trivial)\nunknowns: ';
    const r = parsePartialOutput(out, 0);
    expect(r.verdict).toBe('Depends');
    expect(r.residuals).toEqual([]);
    expect(r.unknowns).toEqual([]);
  });

  it('reports unsupported mode when usage text is returned', () => {
    const r = parsePartialOutput('usage: agent-authz-prover partial ...', 2);
    expect(r.verdict).toBeNull();
    expect(r.reason).toMatch(/does not support partial mode/i);
  });

  it('null verdict + reason when output is inconclusive', () => {
    const r = parsePartialOutput('some garbage', 1);
    expect(r.verdict).toBeNull();
    expect(r.reason).toBe('some garbage');
  });
});

describe('partial-prover — real binary (if available)', () => {
  it('read on an UNKNOWN file → Depends with a path residual', async () => {
    if (!partialProverExists()) {
      console.log('  ⓘ Skipping real partial test — prover binary not found');
      return;
    }
    const r = await probePartial(
      MANDATE,
      { action: 'Ovid::Action::"read"', resource: '?Ovid::File', principal: 'Ovid::Agent::"clawdrey"' },
      { timeoutMs: 10000 },
    );
    expect(r.verdict).toBe('Depends');
    expect(r.residuals.length).toBeGreaterThan(0);
    expect(r.residuals.join(' ')).toContain('.openclaw/workspace');
  });

  it('send on an UNKNOWN channel (out of mandate) → Deny', async () => {
    if (!partialProverExists()) return;
    const r = await probePartial(
      MANDATE,
      { action: 'Ovid::Action::"send"', resource: '?Ovid::Channel', principal: 'Ovid::Agent::"clawdrey"' },
      { timeoutMs: 10000 },
    );
    expect(r.verdict).toBe('Deny');
  });

  it('concrete workspace file read → Allow', async () => {
    if (!partialProverExists()) return;
    const entitiesJson = JSON.stringify([
      {
        uid: { type: 'Ovid::File', id: 'wsfile' },
        attrs: { path: '/Users/clawdreyhepburn/.openclaw/workspace/MEMORY.md' },
        parents: [],
      },
    ]);
    const r = await probePartial(
      MANDATE,
      { action: 'Ovid::Action::"read"', resource: 'Ovid::File::"wsfile"', principal: 'Ovid::Agent::"clawdrey"' },
      { timeoutMs: 10000, entitiesJson },
    );
    expect(r.verdict).toBe('Allow');
  });

  it('probeOptions maps a whole action space', async () => {
    if (!partialProverExists()) return;
    const results = await probeOptions(
      MANDATE,
      [
        { action: 'Ovid::Action::"read"', resource: '?Ovid::File', principal: 'Ovid::Agent::"clawdrey"' },
        { action: 'Ovid::Action::"exec"', resource: '?Ovid::Shell', principal: 'Ovid::Agent::"clawdrey"' },
        { action: 'Ovid::Action::"send"', resource: '?Ovid::Channel', principal: 'Ovid::Agent::"clawdrey"' },
      ],
      { timeoutMs: 10000 },
    );
    expect(results).toHaveLength(3);
    const byAction = Object.fromEntries(results.map((r) => [r.action, r.verdict]));
    expect(byAction['Ovid::Action::"read"']).toBe('Depends');
    expect(byAction['Ovid::Action::"exec"']).toBe('Depends');
    expect(byAction['Ovid::Action::"send"']).toBe('Deny');
  });
});
