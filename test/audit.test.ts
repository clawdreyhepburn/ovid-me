import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { readFileSync, existsSync, unlinkSync } from 'node:fs';
import { createAuditLogger, AuditLogger } from '../src/audit.js';
import { createOvid, generateKeypair } from '@clawdreyhepburn/ovid';
import type { CedarMandate } from '../src/config.js';

const TEST_LOG = '/tmp/ovid-test-audit.jsonl';

const testMandate: CedarMandate = {
  rarFormat: 'cedar',
  policySet: 'permit(principal, action == Ovid::Action::"read_file", resource);',
};

function cleanup() {
  if (existsSync(TEST_LOG)) unlinkSync(TEST_LOG);
}

function readLines(): unknown[] {
  return readFileSync(TEST_LOG, 'utf-8').trim().split('\n').map(l => JSON.parse(l));
}

describe('AuditLogger', () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  it('logs issuance via logger directly', async () => {
    const logger = createAuditLogger(TEST_LOG);
    const keys = await generateKeypair();
    const token = await createOvid({ issuerKeys: keys, mandate: testMandate });
    logger.logIssuance(token.claims);

    const lines = readLines();
    expect(lines).toHaveLength(1);
    const entry = lines[0] as Record<string, unknown>;
    expect(entry.event).toBe('issuance');
    expect(entry.mandate).toBe('present');
    expect(entry.ts).toBeDefined();
  });

  it('logs verification via logger directly', async () => {
    const logger = createAuditLogger(TEST_LOG);
    const keys = await generateKeypair();
    const token = await createOvid({ issuerKeys: keys, mandate: testMandate });

    const result = { valid: true, principal: token.claims.sub, mandate: testMandate, chain: [], expiresIn: 1800 };
    logger.logVerification(token.claims.jti, result);

    const lines = readLines();
    expect(lines).toHaveLength(1);
    const entry = lines[0] as Record<string, unknown>;
    expect(entry.event).toBe('verification');
    expect(entry.valid).toBe(true);
  });

  it('logs decisions', () => {
    const logger = createAuditLogger(TEST_LOG);
    logger.logDecision('agent-1', 'use_tool', 'browser', 'allow', ['policy-1']);

    const lines = readLines();
    expect(lines).toHaveLength(1);
    const entry = lines[0] as Record<string, unknown>;
    expect(entry.event).toBe('decision');
    expect(entry.decision).toBe('allow');
    expect(entry.agentJti).toBe('agent-1');
    expect(entry.policies).toEqual(['policy-1']);
  });

  it('produces valid JSON for all log entry types', () => {
    const logger = createAuditLogger(TEST_LOG);
    logger.logDecision('a', 'exec', 'shell', 'deny');
    logger.logCustom('test-event', { foo: 'bar', num: 42 });

    const lines = readLines();
    expect(lines).toHaveLength(2);
    for (const line of lines) {
      expect(line).toBeTypeOf('object');
      expect((line as Record<string, unknown>).ts).toBeDefined();
    }
  });

  it('does not log when disabled (no path)', () => {
    const logger = new AuditLogger(); // no path, OVID_AUDIT_LOG not set
    logger.logDecision('a', 'exec', 'shell', 'deny');
    expect(existsSync(TEST_LOG)).toBe(false);
  });
});
