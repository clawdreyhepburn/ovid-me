/**
 * End-to-end integration tests: OVID + OVID-ME + Carapace
 *
 * Proves the full authorization stack works together:
 * - OVID: token creation, verification, delegation chains
 * - OVID-ME: mandate evaluation, dry-run mode
 * - Carapace: deployment-level Cedar policy evaluation
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  generateKeypair,
  createOvid,
  verifyOvid,
  exportPublicKeyBase64,
  importPublicKeyBase64,
} from '@clawdreyhepburn/ovid';
import type { CedarMandate, KeyPair, OvidToken } from '@clawdreyhepburn/ovid';

import { evaluateMandate } from '../src/evaluate.js';
import { MandateEngine } from '../src/mandate-engine.js';
import type { PolicySource } from '../src/config.js';

/**
 * Simple PolicySource that reads .cedar files from a temp directory,
 * mimicking Carapace's CarapacePolicySource without cross-package imports.
 */
class MockCarapacePolicySource implements PolicySource {
  constructor(private policyDir: string) {}

  async getEffectivePolicy(_principal: string): Promise<string | null> {
    const { readdirSync, readFileSync } = await import('node:fs');
    const files = readdirSync(this.policyDir).filter(f => f.endsWith('.cedar'));
    if (files.length === 0) return null;
    return files.map(f => readFileSync(join(this.policyDir, f), 'utf-8')).join('\n\n');
  }
}

/**
 * Simulate Carapace's Cedar evaluation (same semantics as CedarEngine.authorize).
 * Default-deny, forbid overrides permit. Uses Jans:: namespace for actions.
 */
function evaluateCarapacePolicy(
  cedarText: string,
  action: string,
): 'allow' | 'deny' {
  // Parse policies (reusing the same pattern as Carapace's CedarEngine)
  const blocks = cedarText.match(/(permit|forbid)\s*\([^;]*;/gs);
  if (!blocks) return 'deny';

  let hasPermit = false;
  for (const block of blocks) {
    const effect = block.trimStart().startsWith('forbid') ? 'forbid' : 'permit';
    // Check action constraint with Jans:: namespace
    const actionMatch = block.match(/action\s*==\s*Jans::Action::"([^"]+)"/);
    if (actionMatch && actionMatch[1] !== action) continue;
    // If no action constraint, it's a wildcard — matches everything

    if (effect === 'forbid') return 'deny';
    if (effect === 'permit') hasPermit = true;
  }

  return hasPermit ? 'allow' : 'deny';
}

describe('Integration: OVID + OVID-ME + Carapace', () => {
  let rootKeys: KeyPair;
  let tmpDir: string;

  beforeEach(async () => {
    rootKeys = await generateKeypair();
    tmpDir = mkdtempSync(join(tmpdir(), 'ovid-integration-'));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('Test 1: Happy path — both layers allow', async () => {
    // 1. Create OVID with read_file mandate scoped to /src/*
    const mandate: CedarMandate = {
      type: 'agent_mandate', rarFormat: 'cedar',
      policySet: 'permit(principal, action == Ovid::Action::"read_file", resource) when { resource.path like "/src/*" };',
    };

    const token = await createOvid({ issuerKeys: rootKeys, mandate });

    // 2. Verify the token
    const result = await verifyOvid(token.jwt, rootKeys.publicKey);
    expect(result.valid).toBe(true);
    expect(result.mandate.policySet).toBe(mandate.policySet);

    // 3. OVID-ME evaluates the mandate → allow
    const mandateResult = evaluateMandate(result.mandate.policySet, {
      action: 'read_file',
      resource: '/src/index.ts',
    });
    expect(mandateResult.decision).toBe('allow');

    // 4. Write Carapace policy to temp dir
    writeFileSync(join(tmpDir, 'allow-read.cedar'), 'permit(principal, action == Jans::Action::"read_file", resource);');

    // 5. Carapace evaluates → allow
    const source = new MockCarapacePolicySource(tmpDir);
    const carapacePolicy = await source.getEffectivePolicy(result.principal);
    expect(carapacePolicy).not.toBeNull();
    const carapaceDecision = evaluateCarapacePolicy(carapacePolicy!, 'read_file');
    expect(carapaceDecision).toBe('allow');

    // 6. Combined: both allow → success
    const combined = mandateResult.decision === 'allow' && carapaceDecision === 'allow' ? 'allow' : 'deny';
    expect(combined).toBe('allow');
  });

  it('Test 2: Carapace blocks, mandate allows', async () => {
    // Broad mandate
    const token = await createOvid({
      issuerKeys: rootKeys,
      mandate: { type: 'agent_mandate', rarFormat: 'cedar', policySet: 'permit(principal, action, resource);' },
    });

    const result = await verifyOvid(token.jwt, rootKeys.publicKey);
    expect(result.valid).toBe(true);

    // OVID-ME: mandate allows exec
    const mandateResult = evaluateMandate(result.mandate.policySet, {
      action: 'exec',
      resource: '/bin/sh',
    });
    expect(mandateResult.decision).toBe('allow');

    // Carapace: forbids exec
    writeFileSync(join(tmpDir, 'block-exec.cedar'), 'forbid(principal, action == Jans::Action::"exec", resource);');
    const source = new MockCarapacePolicySource(tmpDir);
    const carapacePolicy = await source.getEffectivePolicy(result.principal);
    const carapaceDecision = evaluateCarapacePolicy(carapacePolicy!, 'exec');
    expect(carapaceDecision).toBe('deny');

    // Combined: deny (both must allow)
    const combined = mandateResult.decision === 'allow' && carapaceDecision === 'allow' ? 'allow' : 'deny';
    expect(combined).toBe('deny');
  });

  it('Test 3: Mandate blocks, Carapace allows', async () => {
    // Narrow mandate: only read_file
    const token = await createOvid({
      issuerKeys: rootKeys,
      mandate: {
        type: 'agent_mandate', rarFormat: 'cedar',
        policySet: 'permit(principal, action == Ovid::Action::"read_file", resource);',
      },
    });

    const result = await verifyOvid(token.jwt, rootKeys.publicKey);
    expect(result.valid).toBe(true);

    // OVID-ME: mandate denies exec
    const mandateResult = evaluateMandate(result.mandate.policySet, {
      action: 'exec',
      resource: '/bin/sh',
    });
    expect(mandateResult.decision).toBe('deny');

    // Carapace: wide open
    writeFileSync(join(tmpDir, 'allow-all.cedar'), 'permit(principal, action, resource);');
    const source = new MockCarapacePolicySource(tmpDir);
    const carapacePolicy = await source.getEffectivePolicy(result.principal);
    const carapaceDecision = evaluateCarapacePolicy(carapacePolicy!, 'exec');
    expect(carapaceDecision).toBe('allow');

    // Combined: deny
    const combined = mandateResult.decision === 'allow' && carapaceDecision === 'allow' ? 'allow' : 'deny';
    expect(combined).toBe('deny');
  });

  it('Test 4: Dry-run mode logs but does not block', async () => {
    const engine = new MandateEngine({ mandateMode: 'dry-run' });

    // Narrow mandate: only read_file
    const mandate: CedarMandate = {
      type: 'agent_mandate', rarFormat: 'cedar',
      policySet: 'permit(principal, action == Ovid::Action::"read_file", resource);',
    };

    const token = await createOvid({ issuerKeys: rootKeys, mandate });

    // Evaluate exec (would be denied in enforce mode)
    const result = await engine.evaluate(token.claims.jti, mandate, {
      action: 'exec',
      resource: '/bin/sh',
    });

    // Dry-run: allows but logs that it would deny
    expect(result.decision).toBe('allow');
    expect(result.mode).toBe('dry-run');
    expect(result.reason).toContain('dry-run');
    expect(result.reason).toContain('would deny');
  });

  it('Test 5: Parent chain — child mandate within parent scope', async () => {
    // Root OVID with wide mandate
    const rootToken = await createOvid({
      issuerKeys: rootKeys,
      issuer: 'root-orchestrator',
      mandate: { type: 'agent_mandate', rarFormat: 'cedar', policySet: 'permit(principal, action, resource);' },
    });

    // Child OVID with narrow mandate (subset of parent)
    const childToken = await createOvid({
      issuerKeys: rootToken.keys,
      issuerOvid: { jwt: rootToken.jwt, claims: rootToken.claims },
      mandate: {
        type: 'agent_mandate', rarFormat: 'cedar',
        policySet: 'permit(principal, action == Ovid::Action::"read_file", resource);',
      },
    });

    // Verify parent chain (now inside authorization_details)
    const childDetail = childToken.claims.authorization_details[0];
    expect(childDetail.parent_chain!.length).toBe(1);
    expect(childDetail.parent_chain![0]).toBe(rootToken.claims.sub);
    expect(childToken.claims.parent_ovid).toBe(rootToken.claims.jti);

    // Verify child token with root's public key (signed by root's agent keys)
    const childResult = await verifyOvid(childToken.jwt, rootToken.keys.publicKey);
    expect(childResult.valid).toBe(true);

    // Child mandate allows read_file
    const readResult = evaluateMandate(childResult.mandate.policySet, {
      action: 'read_file',
      resource: '/src/index.ts',
    });
    expect(readResult.decision).toBe('allow');

    // Child mandate denies exec (even though parent's mandate would allow it)
    const execResult = evaluateMandate(childResult.mandate.policySet, {
      action: 'exec',
      resource: '/bin/sh',
    });
    expect(execResult.decision).toBe('deny');
  });

  it('Test 6: Cross-domain verification', async () => {
    // Domain A: generate keypair and create OVID
    const domainAKeys = await generateKeypair();
    const domainAToken = await createOvid({
      issuerKeys: domainAKeys,
      issuer: 'domain-a.example.com',
      mandate: {
        type: 'agent_mandate', rarFormat: 'cedar',
        policySet: 'permit(principal, action == Ovid::Action::"read_file", resource);',
      },
    });

    // Domain B: import domain A's public key
    const pubKeyBase64 = await exportPublicKeyBase64(domainAKeys.publicKey);
    const importedKey = await importPublicKeyBase64(pubKeyBase64);

    // Verify domain A's token using imported key in domain B
    const result = await verifyOvid(domainAToken.jwt, importedKey);
    expect(result.valid).toBe(true);
    expect(result.principal).toBe(domainAToken.claims.sub);

    // Evaluate the mandate in domain B → works
    const mandateResult = evaluateMandate(result.mandate.policySet, {
      action: 'read_file',
      resource: '/data/file.txt',
    });
    expect(mandateResult.decision).toBe('allow');

    // Cross-domain mandate still denies unauthorized actions
    const denyResult = evaluateMandate(result.mandate.policySet, {
      action: 'exec',
      resource: '/bin/sh',
    });
    expect(denyResult.decision).toBe('deny');
  });
});
