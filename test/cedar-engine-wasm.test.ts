import { describe, it, expect, vi, beforeEach } from 'vitest';
import { evaluateMandateAsync } from '../src/evaluate.js';
import { isWasmAvailable, _resetWasm } from '../src/cedar-engine-wasm.js';

describe('cedar-engine-wasm', () => {
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

  it('evaluateMandateAsync auto mode falls back when WASM unavailable', async () => {
    _resetWasm();
    const cedar = `permit(principal, action == Ovid::Action::"read_file", resource);`;
    const result = await evaluateMandateAsync(cedar, 'agent-1', { action: 'read_file', resource: '/foo' }, 'auto');
    // Either wasm or fallback — both should produce correct result
    expect(result.decision).toBe('allow');
    expect(['wasm', 'fallback']).toContain(result.engine);
  });

  it('evaluateMandateAsync wasm-only mode returns deny if WASM unavailable', async () => {
    _resetWasm();
    const available = await isWasmAvailable();
    if (!available) {
      const cedar = `permit(principal, action == Ovid::Action::"read_file", resource);`;
      const result = await evaluateMandateAsync(cedar, 'agent-1', { action: 'read_file', resource: '/foo' }, 'wasm');
      expect(result.decision).toBe('deny');
      expect(result.reason).toContain('WASM');
    }
  });
});
