import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { DashboardServer } from '../src/dashboard-server.js';
import { AuditDatabase } from '../src/audit-db.js';
import { writeFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

function tmpDb(): string {
  return join(tmpdir(), `ovid-dash-test-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
}

async function get(port: number, path: string): Promise<{ status: number; body: any; text: string }> {
  const res = await fetch(`http://localhost:${port}${path}`);
  const text = await res.text();
  let body: any;
  try { body = JSON.parse(text); } catch { body = text; }
  return { status: res.status, body, text };
}

async function post(port: number, path: string, data: unknown): Promise<{ status: number; body: any }> {
  const res = await fetch(`http://localhost:${port}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  const text = await res.text();
  let body: any;
  try { body = JSON.parse(text); } catch { body = text; }
  return { status: res.status, body };
}

describe('Dashboard HTML', () => {
  it('embedded JavaScript is syntactically valid', async () => {
    const { dashboardHtml } = await import('../src/dashboard-html.js');
    const html = dashboardHtml();
    const scriptMatch = html.match(/<script[^>]*>([\s\S]*?)<\/script>/);
    expect(scriptMatch).toBeTruthy();
    const js = scriptMatch![1];
    expect(() => new Function(js)).not.toThrow();
  });
});

describe('Dashboard Server - Empty', () => {
  let server: DashboardServer;
  let port: number;
  let dbPath: string;

  beforeAll(async () => {
    dbPath = tmpDb();
    server = new DashboardServer({ port: 0, dbPath });
    await server.start();
    // Extract actual port
    port = (server as any).server.address().port;
  });

  afterAll(async () => {
    await server.stop();
    try { unlinkSync(dbPath); } catch {}
    try { unlinkSync(dbPath + '-wal'); } catch {}
    try { unlinkSync(dbPath + '-shm'); } catch {}
  });

  it('serves HTML on GET /', async () => {
    const { status, text } = await get(port, '/');
    expect(status).toBe(200);
    expect(text).toContain('<!DOCTYPE html>');
    expect(text).toContain('OVID');
  });

  it('GET /api/overview returns correct structure when empty', async () => {
    const { status, body } = await get(port, '/api/overview');
    expect(status).toBe(200);
    expect(body).toHaveProperty('totalAgents', 0);
    expect(body).toHaveProperty('totalDecisions', 0);
    expect(body).toHaveProperty('breakdown');
    expect(body).toHaveProperty('anomalyCount', 0);
  });

  it('GET /api/agents returns empty array', async () => {
    const { status, body } = await get(port, '/api/agents');
    expect(status).toBe(200);
    expect(body).toEqual([]);
  });

  it('returns 404 on unknown routes', async () => {
    const { status } = await get(port, '/api/nonexistent');
    expect(status).toBe(404);
  });

  it('returns 404 on non-API routes', async () => {
    const { status } = await get(port, '/random');
    expect(status).toBe(404);
  });
});

describe('Dashboard Server - Seeded Data', () => {
  let server: DashboardServer;
  let db: AuditDatabase;
  let port: number;
  let dbPath: string;

  // Timestamps spread across 3 hours
  const BASE_TS = 1700000000; // ~2023-11-14
  const HOUR1 = BASE_TS;
  const HOUR2 = BASE_TS + 3600;
  const HOUR3 = BASE_TS + 7200;

  beforeAll(async () => {
    dbPath = tmpDb();
    server = new DashboardServer({ port: 0, dbPath });
    await server.start();
    port = (server as any).server.address().port;
    db = server.getDatabase();

    // Seed agents
    db.recordIssuance({ jti: 'clawdrey', iss: 'system', role: 'orchestrator', parent_chain: [], iat: HOUR1, exp: HOUR1 + 86400 });
    db.recordIssuance({ jti: 'code-reviewer', iss: 'clawdrey', role: 'code-reviewer', parent_chain: ['clawdrey'], iat: HOUR1, exp: HOUR1 + 86400 });
    db.recordIssuance({ jti: 'browser-worker', iss: 'clawdrey', role: 'browser-worker', parent_chain: ['clawdrey'], iat: HOUR1, exp: HOUR1 + 86400 });
    db.recordIssuance({ jti: 'deploy-agent', iss: 'clawdrey', role: 'deploy-agent', parent_chain: ['clawdrey'], iat: HOUR1, exp: HOUR1 + 86400 });
    db.recordIssuance({ jti: 'reader', iss: 'code-reviewer', role: 'reader', parent_chain: ['clawdrey', 'code-reviewer'], iat: HOUR2, exp: HOUR2 + 86400 });

    // Seed decisions across hours, mix of types
    // Hour 1 decisions
    db.recordDecisionAt(HOUR1 + 100, 'clawdrey', 'spawn_agent', 'code-reviewer', 'allow-proven', ['policy-delegation']);
    db.recordDecisionAt(HOUR1 + 200, 'clawdrey', 'spawn_agent', 'browser-worker', 'allow-proven', ['policy-delegation']);
    db.recordDecisionAt(HOUR1 + 300, 'clawdrey', 'spawn_agent', 'deploy-agent', 'allow-proven', ['policy-delegation']);
    db.recordDecisionAt(HOUR1 + 400, 'code-reviewer', 'read_file', '/src/main.ts', 'allow-proven', ['policy-read']);
    db.recordDecisionAt(HOUR1 + 500, 'code-reviewer', 'read_file', '/src/lib.ts', 'allow-proven', ['policy-read']);
    db.recordDecisionAt(HOUR1 + 600, 'browser-worker', 'use_tool', 'browser', 'allow-unproven', ['policy-tools']);
    db.recordDecisionAt(HOUR1 + 700, 'browser-worker', 'navigate', 'https://example.com', 'allow-unproven', ['policy-tools']);
    db.recordDecisionAt(HOUR1 + 800, 'deploy-agent', 'exec', 'npm run build', 'allow-proven', ['policy-deploy']);
    db.recordDecisionAt(HOUR1 + 900, 'deploy-agent', 'exec', 'rm -rf /', 'deny', ['policy-safety']);

    // Hour 2 decisions
    db.recordDecisionAt(HOUR2 + 100, 'clawdrey', 'spawn_agent', 'reader', 'allow-proven', ['policy-delegation']);
    db.recordDecisionAt(HOUR2 + 200, 'reader', 'read_file', '/docs/readme.md', 'allow-proven', ['policy-read']);
    db.recordDecisionAt(HOUR2 + 300, 'reader', 'read_file', '/etc/passwd', 'deny', ['policy-safety']);
    db.recordDecisionAt(HOUR2 + 400, 'code-reviewer', 'exec', 'git diff', 'allow-proven', ['policy-read']);
    db.recordDecisionAt(HOUR2 + 500, 'browser-worker', 'use_tool', 'screenshot', 'allow-unproven', ['policy-tools']);
    db.recordDecisionAt(HOUR2 + 600, 'deploy-agent', 'exec', 'docker push', 'allow-proven', ['policy-deploy']);

    // Hour 3 decisions
    db.recordDecisionAt(HOUR3 + 100, 'clawdrey', 'read_file', '/status', 'allow-proven', ['policy-read']);
    db.recordDecisionAt(HOUR3 + 200, 'code-reviewer', 'write_file', '/src/fix.ts', 'allow-proven', ['policy-write']);
    db.recordDecisionAt(HOUR3 + 300, 'browser-worker', 'navigate', 'https://evil.com', 'deny', ['policy-safety']);
    db.recordDecisionAt(HOUR3 + 400, 'deploy-agent', 'exec', 'kubectl apply', 'allow-proven', ['policy-deploy']);
    db.recordDecisionAt(HOUR3 + 500, 'reader', 'read_file', '/src/utils.ts', 'allow-proven', ['policy-read']);
  });

  afterAll(async () => {
    await server.stop();
    try { unlinkSync(dbPath); } catch {}
    try { unlinkSync(dbPath + '-wal'); } catch {}
    try { unlinkSync(dbPath + '-shm'); } catch {}
  });

  it('GET /api/overview reflects correct counts', async () => {
    const { body } = await get(port, '/api/overview');
    expect(body.totalAgents).toBe(5);
    expect(body.totalDecisions).toBe(20);
    expect(body.breakdown).toBeInstanceOf(Array);
    const proven = body.breakdown.find((b: any) => b.decision === 'allow-proven');
    const unproven = body.breakdown.find((b: any) => b.decision === 'allow-unproven');
    const deny = body.breakdown.find((b: any) => b.decision === 'deny');
    expect(proven.count).toBe(14);
    expect(unproven.count).toBe(3);
    expect(deny.count).toBe(3);
  });

  it('GET /api/agents returns all agents', async () => {
    const { body } = await get(port, '/api/agents');
    expect(body.length).toBe(5);
    const clawdrey = body.find((a: any) => a.agent_jti === 'clawdrey');
    expect(clawdrey).toBeDefined();
    expect(clawdrey.role).toBe('orchestrator');
    expect(clawdrey).toHaveProperty('decision_count');
    expect(clawdrey).toHaveProperty('deny_count');
  });

  it('GET /api/agents/:jti returns agent detail + decisions', async () => {
    const { body } = await get(port, '/api/agents/code-reviewer');
    expect(body.agent).toBeDefined();
    expect(body.agent.jti).toBe('code-reviewer');
    expect(body.agent.role).toBe('code-reviewer');
    expect(body.decisions).toBeInstanceOf(Array);
    expect(body.decisions.length).toBe(4); // read_file x2, exec, write_file
  });

  it('GET /api/agents/:jti/tree returns delegation tree', async () => {
    const { body } = await get(port, '/api/agents/clawdrey/tree');
    expect(body).toBeInstanceOf(Array);
    // clawdrey + 3 children + 1 grandchild = 5
    expect(body.length).toBe(5);
    const reader = body.find((n: any) => n.jti === 'reader');
    expect(reader).toBeDefined();
    expect(reader.depth).toBe(2);
  });

  it('GET /api/decisions returns paginated decisions', async () => {
    const { body } = await get(port, '/api/decisions?limit=5');
    expect(body.length).toBe(5);
  });

  it('GET /api/decisions?agent=X filters correctly', async () => {
    const { body } = await get(port, '/api/decisions?agent=browser-worker');
    expect(body.length).toBe(4);
    expect(body.every((d: any) => d.agent_jti === 'browser-worker')).toBe(true);
  });

  it('GET /api/decisions?decision=deny filters correctly', async () => {
    const { body } = await get(port, '/api/decisions?decision=deny');
    expect(body.length).toBe(3);
    expect(body.every((d: any) => d.decision === 'deny')).toBe(true);
  });

  it('GET /api/timeline returns hourly buckets', async () => {
    const { body } = await get(port, '/api/timeline');
    expect(body).toBeInstanceOf(Array);
    expect(body.length).toBe(3); // 3 hours
    expect(body[0]).toHaveProperty('hour');
    expect(body[0]).toHaveProperty('proven');
    expect(body[0]).toHaveProperty('deny');
    expect(body[0]).toHaveProperty('total');
  });

  it('GET /api/policies returns policy usage', async () => {
    const { body } = await get(port, '/api/policies');
    expect(body).toBeInstanceOf(Array);
    expect(body.length).toBeGreaterThan(0);
    const delegation = body.find((p: any) => p.policy === 'policy-delegation');
    expect(delegation).toBeDefined();
    expect(delegation.count).toBe(4);
  });

  it('GET /api/actions returns action breakdown', async () => {
    const { body } = await get(port, '/api/actions');
    expect(body).toBeInstanceOf(Array);
    const readFile = body.find((a: any) => a.action === 'read_file');
    expect(readFile).toBeDefined();
  });

  it('GET /api/roles returns role activity', async () => {
    const { body } = await get(port, '/api/roles');
    expect(body).toBeInstanceOf(Array);
    const orchestrator = body.find((r: any) => r.role === 'orchestrator');
    expect(orchestrator).toBeDefined();
    expect(orchestrator.agent_count).toBe(1);
    expect(orchestrator.decision_count).toBe(5); // 4 spawns + 1 read
    const reviewer = body.find((r: any) => r.role === 'code-reviewer');
    expect(reviewer.agent_count).toBe(1);
    expect(reviewer.decision_count).toBe(4);
    expect(reviewer.deny_count).toBe(0);
  });

  it('GET /api/roles/:role returns actions for that role', async () => {
    const { body } = await get(port, '/api/roles/deploy-agent');
    expect(body).toBeInstanceOf(Array);
    expect(body.length).toBeGreaterThan(0);
    expect(body.every((r: any) => r.action && r.decision !== undefined)).toBe(true);
  });

  it('GET /api/roles/timeline returns hourly role data', async () => {
    const { body } = await get(port, '/api/roles/timeline');
    expect(body).toBeInstanceOf(Array);
    expect(body.length).toBeGreaterThan(0);
    expect(body[0]).toHaveProperty('hour');
    expect(body[0]).toHaveProperty('role');
    expect(body[0]).toHaveProperty('count');
  });

  it('GET /api/sankey returns nodes and links', async () => {
    const { body } = await get(port, '/api/sankey');
    expect(body).toHaveProperty('nodes');
    expect(body).toHaveProperty('links');
    expect(body.nodes.length).toBeGreaterThan(0);
    expect(body.links.length).toBeGreaterThan(0);
  });

  it('GET /api/depth returns depth breakdown', async () => {
    const { body } = await get(port, '/api/depth');
    expect(body).toBeInstanceOf(Array);
    expect(body.length).toBeGreaterThan(0);
    expect(body[0]).toHaveProperty('depth');
    expect(body[0]).toHaveProperty('decision');
    expect(body[0]).toHaveProperty('count');
  });

  it('GET /api/anomalies returns correct structure', async () => {
    const { body } = await get(port, '/api/anomalies');
    expect(body).toHaveProperty('unproven');
    expect(body).toHaveProperty('deepChains');
    expect(body).toHaveProperty('rapidSpawning');
    expect(body.unproven.length).toBe(3); // 3 allow-unproven decisions
  });

  it('time range filtering works end-to-end', async () => {
    // Only hour 2
    const { body } = await get(port, `/api/overview?from=${HOUR2}&to=${HOUR2 + 3599}`);
    expect(body.totalDecisions).toBe(6); // 6 decisions in hour 2
  });

  it('time range filtering on decisions endpoint', async () => {
    const { body } = await get(port, `/api/decisions?from=${HOUR3}&to=${HOUR3 + 3599}`);
    expect(body.length).toBe(5); // 5 decisions in hour 3
  });

  it('time range filtering on timeline', async () => {
    const { body } = await get(port, `/api/timeline?from=${HOUR1}&to=${HOUR1 + 3599}`);
    expect(body.length).toBe(1); // just hour 1
    expect(body[0].total).toBe(9);
  });

  it('POST /api/import imports JSONL correctly', async () => {
    const logPath = join(tmpdir(), `ovid-import-test-${Date.now()}.jsonl`);
    const lines = [
      JSON.stringify({ ts: '2025-06-01T00:00:00Z', event: 'issuance', jti: 'imported-1', iss: 'root', role: 'tester', parent_chain: [], exp: 9999999999 }),
      JSON.stringify({ ts: '2025-06-01T00:01:00Z', event: 'decision', agentJti: 'imported-1', action: 'test', resource: 'foo', decision: 'allow-proven', policies: ['p1'] }),
    ];
    writeFileSync(logPath, lines.join('\n'));
    const { status, body } = await post(port, '/api/import', { path: logPath });
    expect(status).toBe(200);
    expect(body.imported).toBe(2);
    try { unlinkSync(logPath); } catch {}
  });

  it('POST /api/import handles invalid JSON body', async () => {
    const res = await fetch(`http://localhost:${port}/api/import`, {
      method: 'POST',
      body: 'not json',
    });
    expect(res.status).toBe(400);
  });

  it('handles URL-encoded JTI with slashes', async () => {
    // Register an agent with slashes in JTI
    db.recordIssuance({ jti: 'org/team/agent-1', iss: 'clawdrey', role: 'special', parent_chain: ['clawdrey'], iat: HOUR1, exp: HOUR1 + 86400 });
    db.recordDecisionAt(HOUR1 + 50, 'org/team/agent-1', 'test', 'res', 'allow-proven', ['p1']);
    const encoded = encodeURIComponent('org/team/agent-1');
    const { body } = await get(port, `/api/agents/${encoded}`);
    expect(body.agent).toBeDefined();
    expect(body.agent.jti).toBe('org/team/agent-1');
    expect(body.decisions.length).toBe(1);
  });
});
