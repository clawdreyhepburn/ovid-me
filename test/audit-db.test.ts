import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { AuditDatabase } from '../src/audit-db.js';
import { writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

function tmpDb(): string {
  return join(tmpdir(), `ovid-test-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
}

describe('AuditDatabase', () => {
  let db: AuditDatabase;
  let dbPath: string;

  beforeEach(() => {
    dbPath = tmpDb();
    db = new AuditDatabase(dbPath);
  });

  afterEach(() => {
    db.close();
    try { unlinkSync(dbPath); } catch {}
    try { unlinkSync(dbPath + '-wal'); } catch {}
    try { unlinkSync(dbPath + '-shm'); } catch {}
  });

  it('creates tables on init', () => {
    // If we got here without error, tables were created
    expect(db).toBeDefined();
  });

  it('records and queries issuance', () => {
    db.recordIssuance({
      jti: 'agent-1', iss: 'root', role: 'coder',
      parent_chain: [], iat: 1000, exp: 2000,
    });
    const agent = db.getAgent('agent-1') as any;
    expect(agent).toBeDefined();
    expect(agent.jti).toBe('agent-1');
    expect(agent.role).toBe('coder');
    expect(agent.depth).toBe(0);
  });

  it('records chain relationships', () => {
    db.recordIssuance({ jti: 'root-1', iss: 'system', role: 'orchestrator', parent_chain: [], iat: 1000, exp: 2000 });
    db.recordIssuance({ jti: 'child-1', iss: 'root-1', role: 'coder', parent_chain: ['root-1'], iat: 1000, exp: 2000 });
    const tree = db.getAgentTree('root-1') as any[];
    expect(tree.length).toBe(2);
    expect(tree.some(n => n.jti === 'child-1')).toBe(true);
  });

  it('records decisions and queries history', () => {
    db.recordIssuance({ jti: 'a1', iss: 'root', role: 'coder', parent_chain: [], iat: 1000, exp: 2000 });
    db.recordDecision('a1', 'read_file', '/etc/passwd', 'deny', ['policy-no-etc']);
    db.recordDecision('a1', 'use_tool', 'web_search', 'allow-proven', ['policy-tools']);
    const history = db.getAgentHistory('a1') as any[];
    expect(history.length).toBe(2);
  });

  it('computes decision breakdown', () => {
    db.recordIssuance({ jti: 'a1', iss: 'root', role: 'coder', parent_chain: [], iat: 1000, exp: 2000 });
    db.recordDecision('a1', 'act1', 'r1', 'deny');
    db.recordDecision('a1', 'act2', 'r2', 'allow-proven');
    db.recordDecision('a1', 'act3', 'r3', 'allow-proven');
    const breakdown = db.getDecisionBreakdown() as any[];
    const deny = breakdown.find(b => b.decision === 'deny');
    const proven = breakdown.find(b => b.decision === 'allow-proven');
    expect(deny?.count).toBe(1);
    expect(proven?.count).toBe(2);
  });

  it('computes action breakdown', () => {
    db.recordIssuance({ jti: 'a1', iss: 'root', role: 'coder', parent_chain: [], iat: 1000, exp: 2000 });
    db.recordDecision('a1', 'read_file', 'r1', 'allow-proven');
    db.recordDecision('a1', 'read_file', 'r2', 'allow-proven');
    db.recordDecision('a1', 'exec_cmd', 'r3', 'deny');
    const actions = db.getActionBreakdown() as any[];
    expect(actions[0].action).toBe('read_file');
    expect(actions[0].count).toBe(2);
  });

  it('time-range filtering works', () => {
    db.recordIssuance({ jti: 'a1', iss: 'root', role: 'coder', parent_chain: [], iat: 1000, exp: 9999999999 });
    db.recordDecisionAt(1000, 'a1', 'act1', 'r1', 'deny');
    db.recordDecisionAt(2000, 'a1', 'act2', 'r2', 'allow-proven');
    db.recordDecisionAt(3000, 'a1', 'act3', 'r3', 'allow-proven');
    const filtered = db.getDecisionBreakdown(1500, 2500) as any[];
    expect(filtered.length).toBe(1);
    expect(filtered[0].decision).toBe('allow-proven');
    expect(filtered[0].count).toBe(1);
  });

  it('detects anomalies - deep chains', () => {
    db.recordIssuance({ jti: 'deep', iss: 'root', role: 'worker', parent_chain: ['a','b','c','d'], iat: 1000, exp: 2000 });
    const anomalies = db.getAnomalies();
    expect(anomalies.deepChains.length).toBe(1);
  });

  it('detects anomalies - unproven decisions', () => {
    db.recordIssuance({ jti: 'a1', iss: 'root', role: 'coder', parent_chain: [], iat: 1000, exp: 2000 });
    db.recordDecision('a1', 'act1', 'r1', 'allow-unproven');
    const anomalies = db.getAnomalies();
    expect(anomalies.unproven.length).toBe(1);
  });

  it('imports JSONL', () => {
    const logPath = join(tmpdir(), `ovid-test-log-${Date.now()}.jsonl`);
    const lines = [
      JSON.stringify({ ts: '2025-01-01T00:00:00Z', event: 'issuance', jti: 'j1', sub: 'j1', iss: 'root', role: 'coder', parent_chain: [], exp: 9999999999 }),
      JSON.stringify({ ts: '2025-01-01T00:01:00Z', event: 'decision', agentJti: 'j1', action: 'read_file', resource: '/foo', decision: 'allow-proven', policies: ['p1'] }),
    ];
    writeFileSync(logPath, lines.join('\n'));
    const result = db.importJsonl(logPath);
    expect(result.imported).toBe(2);
    const agent = db.getAgent('j1') as any;
    expect(agent).toBeDefined();
    const history = db.getAgentHistory('j1') as any[];
    expect(history.length).toBe(1);
    try { unlinkSync(logPath); } catch {}
  });

  it('getOverview returns correct structure', () => {
    db.recordIssuance({ jti: 'a1', iss: 'root', role: 'coder', parent_chain: [], iat: 1000, exp: 2000 });
    db.recordDecision('a1', 'act', 'res', 'allow-proven');
    db.recordDecision('a1', 'act', 'res', 'deny');
    const overview = db.getOverview() as any;
    expect(overview.totalAgents).toBe(1);
    expect(overview.totalDecisions).toBe(2);
    expect(overview.breakdown.length).toBe(2);
  });

  it('policy usage tracking', () => {
    db.recordIssuance({ jti: 'a1', iss: 'root', role: 'coder', parent_chain: [], iat: 1000, exp: 2000 });
    db.recordDecision('a1', 'act', 'res', 'allow-proven', ['policy-a', 'policy-b']);
    db.recordDecision('a1', 'act', 'res', 'deny', ['policy-a']);
    const usage = db.getPolicyUsage() as any[];
    expect(usage[0].policy).toBe('policy-a');
    expect(usage[0].count).toBe(2);
  });

  it('getSankeyData returns nodes and links', () => {
    db.recordIssuance({ jti: 'a1', iss: 'root', role: 'coder', parent_chain: [], iat: 1000, exp: 2000 });
    db.recordDecision('a1', 'read_file', '/foo', 'allow-proven');
    const sankey = db.getSankeyData() as any;
    expect(sankey.nodes.length).toBeGreaterThan(0);
    expect(sankey.links.length).toBeGreaterThan(0);
  });

  it('getRoleActivity breaks down by role', () => {
    db.recordIssuance({ jti: 'r1', iss: 'root', role: 'code-reviewer', parent_chain: [], iat: 1000, exp: 2000 });
    db.recordIssuance({ jti: 'r2', iss: 'root', role: 'code-reviewer', parent_chain: [], iat: 1000, exp: 2000 });
    db.recordIssuance({ jti: 'b1', iss: 'root', role: 'browser-worker', parent_chain: [], iat: 1000, exp: 2000 });
    db.recordDecision('r1', 'read_file', '/src', 'allow-proven');
    db.recordDecision('r2', 'read_file', '/lib', 'allow-proven');
    db.recordDecision('r2', 'exec', 'git', 'deny');
    db.recordDecision('b1', 'use_tool', 'browser', 'allow-unproven');
    const roles = db.getRoleActivity() as any[];
    expect(roles.length).toBe(2);
    const reviewer = roles.find(r => r.role === 'code-reviewer');
    expect(reviewer.agent_count).toBe(2);
    expect(reviewer.decision_count).toBe(3);
    expect(reviewer.deny_count).toBe(1);
    const worker = roles.find(r => r.role === 'browser-worker');
    expect(worker.agent_count).toBe(1);
    expect(worker.unproven_count).toBe(1);
  });

  it('getRoleActions shows actions for a specific role', () => {
    db.recordIssuance({ jti: 'a1', iss: 'root', role: 'coder', parent_chain: [], iat: 1000, exp: 2000 });
    db.recordDecision('a1', 'read_file', '/src', 'allow-proven');
    db.recordDecision('a1', 'exec', 'npm test', 'allow-proven');
    db.recordDecision('a1', 'exec', 'rm -rf', 'deny');
    const actions = db.getRoleActions('coder') as any[];
    expect(actions.length).toBe(3);
    const deny = actions.find(a => a.decision === 'deny');
    expect(deny.action).toBe('exec');
  });

  it('getTopAgents respects limit', () => {
    for (let i = 0; i < 5; i++) {
      db.recordIssuance({ jti: `a${i}`, iss: 'root', role: 'worker', parent_chain: [], iat: 1000, exp: 2000 });
      for (let j = 0; j <= i; j++) db.recordDecision(`a${i}`, 'act', 'res', 'allow-proven');
    }
    const top = db.getTopAgents(undefined, undefined, 3) as any[];
    expect(top.length).toBe(3);
    expect(top[0].decision_count).toBeGreaterThanOrEqual(top[1].decision_count);
  });
});
