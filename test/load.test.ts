import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { AuditDatabase } from '../src/audit-db.js';
import { unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

function tmpDb(): string {
  return join(tmpdir(), `ovid-load-test-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
}

describe('Load Tests', () => {
  let db: AuditDatabase;
  let dbPath: string;

  const ROLES = ['orchestrator', 'code-reviewer', 'browser-worker', 'deploy-agent', 'reader', 'writer', 'tester', 'monitor', 'scheduler', 'auditor'];
  const ACTIONS = ['read_file', 'write_file', 'exec', 'use_tool', 'navigate', 'spawn_agent', 'delete', 'deploy'];
  const DECISIONS = ['allow-proven', 'allow-unproven', 'deny'];
  const POLICIES = ['policy-read', 'policy-write', 'policy-exec', 'policy-safety', 'policy-deploy'];
  const BASE_TS = 1700000000;
  const NUM_AGENTS = 100;
  const NUM_DECISIONS = 10000;

  beforeAll(() => {
    dbPath = tmpDb();
    db = new AuditDatabase(dbPath);

    // Insert 100 agents across 10 roles
    for (let i = 0; i < NUM_AGENTS; i++) {
      const role = ROLES[i % ROLES.length];
      const parentChain = i < 10 ? [] : [`agent-${i % 10}`];
      db.recordIssuance({
        jti: `agent-${i}`, iss: i < 10 ? 'system' : `agent-${i % 10}`,
        role, parent_chain: parentChain,
        iat: BASE_TS + i * 60, exp: BASE_TS + 86400,
      });
    }

    // Insert 10,000 decisions spread across ~10 hours
    for (let i = 0; i < NUM_DECISIONS; i++) {
      const agentIdx = i % NUM_AGENTS;
      const action = ACTIONS[i % ACTIONS.length];
      const decision = DECISIONS[i % DECISIONS.length];
      const policy = [POLICIES[i % POLICIES.length]];
      const ts = BASE_TS + Math.floor(i / (NUM_DECISIONS / 36000)) ; // spread across hours
      db.recordDecisionAt(ts, `agent-${agentIdx}`, action, `/resource/${i}`, decision, policy);
    }
  });

  afterAll(() => {
    db.close();
    try { unlinkSync(dbPath); } catch {}
    try { unlinkSync(dbPath + '-wal'); } catch {}
    try { unlinkSync(dbPath + '-shm'); } catch {}
  });

  it('getRoleActivity completes in < 100ms', () => {
    const start = performance.now();
    const result = db.getRoleActivity() as any[];
    const elapsed = performance.now() - start;
    expect(result.length).toBe(ROLES.length);
    expect(elapsed).toBeLessThan(100);
    console.log(`getRoleActivity: ${elapsed.toFixed(1)}ms, ${result.length} roles`);
  });

  it('getHourlyActivity completes in < 100ms', () => {
    const start = performance.now();
    const result = db.getHourlyActivity() as any[];
    const elapsed = performance.now() - start;
    expect(result.length).toBeGreaterThan(0);
    expect(elapsed).toBeLessThan(100);
    console.log(`getHourlyActivity: ${elapsed.toFixed(1)}ms, ${result.length} buckets`);
  });

  it('getSankeyData completes in < 200ms', () => {
    const start = performance.now();
    const result = db.getSankeyData() as any;
    const elapsed = performance.now() - start;
    expect(result.nodes.length).toBeGreaterThan(0);
    expect(elapsed).toBeLessThan(200);
    console.log(`getSankeyData: ${elapsed.toFixed(1)}ms, ${result.nodes.length} nodes, ${result.links.length} links`);
  });

  it('getOverview completes in < 100ms', () => {
    const start = performance.now();
    const result = db.getOverview() as any;
    const elapsed = performance.now() - start;
    expect(result.totalDecisions).toBe(NUM_DECISIONS);
    expect(elapsed).toBeLessThan(100);
    console.log(`getOverview: ${elapsed.toFixed(1)}ms, ${result.totalDecisions} decisions`);
  });
});
