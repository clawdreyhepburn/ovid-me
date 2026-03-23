import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { resolveConfig, DEFAULT_CONFIG } from '../src/config.js';

describe('resolveConfig', () => {
  const savedEnv: Record<string, string | undefined> = {};
  const envKeys = [
    'OVID_MODE', 'OVID_DEFAULT_TTL', 'OVID_MAX_TTL', 'OVID_MAX_DEPTH',
    'OVID_PROOF', 'OVID_PROOF_FAILURE', 'OVID_ENFORCEMENT_FAILURE',
    'OVID_AUDIT_LOG', 'OVID_AUDIT_DB',
  ];

  beforeEach(() => {
    for (const k of envKeys) {
      savedEnv[k] = process.env[k];
      delete process.env[k];
    }
  });

  afterEach(() => {
    for (const k of envKeys) {
      if (savedEnv[k] === undefined) delete process.env[k];
      else process.env[k] = savedEnv[k];
    }
  });

  it('returns DEFAULT_CONFIG values with no args', () => {
    const config = resolveConfig();
    expect(config.mandateMode).toBe('enforce');
    expect(config.subsetProof).toBe('off');
    expect(config.defaultTtl).toBe(1800);
    expect(config.maxTtl).toBe(86400);
    expect(config.maxChainDepth).toBe(5);
    expect(config.enforcementFailure).toBe('closed');
    expect(config.policySource).toBeNull();
    expect(config.dashboardPort).toBe(19831);
  });

  it('merges partial config, keeping other defaults', () => {
    const config = resolveConfig({ mandateMode: 'dry-run' });
    expect(config.mandateMode).toBe('dry-run');
    expect(config.defaultTtl).toBe(DEFAULT_CONFIG.defaultTtl);
    expect(config.maxChainDepth).toBe(DEFAULT_CONFIG.maxChainDepth);
  });

  it('warns when subsetProof != "off" but no policySource', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    resolveConfig({ subsetProof: 'required' });
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('subsetProof'),
      expect.anything(),
    );
    warnSpy.mockRestore();
  });

  it('warns when mandateMode == "shadow" but no shadowMandate', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    resolveConfig({ mandateMode: 'shadow' });
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('shadow'),
    );
    warnSpy.mockRestore();
  });

  it('environment variable overrides work', () => {
    process.env.OVID_MODE = 'dry-run';
    process.env.OVID_DEFAULT_TTL = '999';
    process.env.OVID_MAX_TTL = '5000';
    process.env.OVID_MAX_DEPTH = '10';

    const config = resolveConfig({});
    expect(config.mandateMode).toBe('dry-run');
    expect(config.defaultTtl).toBe(999);
    expect(config.maxTtl).toBe(5000);
    expect(config.maxChainDepth).toBe(10);
  });

  it('explicit config takes priority over env vars for mandateMode', () => {
    process.env.OVID_MODE = 'dry-run';
    const config = resolveConfig({ mandateMode: 'shadow' });
    // shadow was explicitly set, not default, so env shouldn't override
    expect(config.mandateMode).toBe('shadow');
  });
});
