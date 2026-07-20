import { describe, it, expect, beforeEach } from 'vitest';
import { evaluateMandateAsync } from '../src/evaluate.js';
import { isWasmAvailable, _resetWasm, evaluateWithWasm } from '../src/cedar-engine-wasm.js';

describe('cedar-engine-wasm', () => {
  beforeEach(() => {
    _resetWasm();
  });

  it('isWasmAvailable returns a boolean', async () => {
    const available = await isWasmAvailable();
    expect(typeof available).toBe('boolean');
  });

  it('evaluateMandateAsync with fallback engine works', async () => {
    const cedar = `permit(principal, action == Ovid::Action::"read_file", resource);`;
    const result = await evaluateMandateAsync(cedar, 'agent-1', { action: 'read_file', resource: '/foo' }, 'fallback');
    expect(result.decision).toBe('allow');
    expect(result.engine).toBe('fallback');
  });

  it('evaluateMandateAsync fallback denies unmatched action', async () => {
    const cedar = `permit(principal, action == Ovid::Action::"read_file", resource);`;
    const result = await evaluateMandateAsync(cedar, 'agent-1', { action: 'exec', resource: '/foo' }, 'fallback');
    expect(result.decision).toBe('deny');
    expect(result.engine).toBe('fallback');
  });

  it('evaluateMandateAsync auto mode uses wasm when available (no silent matcher)', async () => {
    const cedar = `permit(principal, action == Ovid::Action::"read_file", resource);`;
    const result = await evaluateMandateAsync(cedar, 'agent-1', { action: 'read_file', resource: '/foo' }, 'auto');
    const available = await isWasmAvailable();
    if (available) {
      expect(result.engine).toBe('wasm');
      expect(result.decision).toBe('allow');
    } else {
      // Fail-closed — does NOT silently use the string matcher.
      expect(result.decision).toBe('deny');
      expect(result.engine).toBe('wasm');
      expect(result.reason).toMatch(/fail-closed|unavailable/i);
    }
  });

  it('evaluateMandateAsync wasm-only mode returns deny if WASM unavailable', async () => {
    const available = await isWasmAvailable();
    if (!available) {
      const cedar = `permit(principal, action == Ovid::Action::"read_file", resource);`;
      const result = await evaluateMandateAsync(cedar, 'agent-1', { action: 'read_file', resource: '/foo' }, 'wasm');
      expect(result.decision).toBe('deny');
      expect(result.reason).toMatch(/WASM|fail-closed/i);
      expect(result.engine).toBe('wasm');
    }
  });

  it('when-clause context gating works under wasm (no silent fallback)', async () => {
    if (!(await isWasmAvailable())) return;

    const cedar = `
permit(principal, action, resource);
forbid(
  principal,
  action == Action::"write_file",
  resource == File::"notes"
) when { context.path like "*secret*" };
`;
    const matching = await evaluateWithWasm(cedar, 'agent-1', {
      action: 'write_file',
      resource: 'notes',
      resourceType: 'File',
      context: { path: '/tmp/secret/x.txt' },
    });
    const nonMatching = await evaluateWithWasm(cedar, 'agent-1', {
      action: 'write_file',
      resource: 'notes',
      resourceType: 'File',
      context: { path: '/tmp/public/x.txt' },
    });

    expect(matching).not.toBeNull();
    expect(nonMatching).not.toBeNull();
    expect(matching!.decision).toBe('deny');
    expect(nonMatching!.decision).toBe('allow');
  });
});
