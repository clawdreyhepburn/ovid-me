import Database from 'better-sqlite3';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export class AuditDatabase {
  private db: Database.Database;

  constructor(dbPath?: string) {
    const p = dbPath ?? join(homedir(), '.ovid', 'audit.db');
    mkdirSync(dirname(p), { recursive: true });
    this.db = new Database(p);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.createTables();
    this.migrate();
  }

  private createTables(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS ovids (
        jti TEXT PRIMARY KEY,
        mandate_summary TEXT,
        issuer TEXT,
        parent_chain TEXT DEFAULT '[]',
        issued_at INTEGER,
        expires_at INTEGER,
        raw_jwt TEXT,
        depth INTEGER DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS decisions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER,
        agent_jti TEXT,
        action TEXT,
        resource TEXT,
        decision TEXT,
        determining_policies TEXT DEFAULT '[]',
        FOREIGN KEY (agent_jti) REFERENCES ovids(jti)
      );
      CREATE TABLE IF NOT EXISTS chains (
        parent_jti TEXT,
        child_jti TEXT,
        PRIMARY KEY (parent_jti, child_jti)
      );
      CREATE INDEX IF NOT EXISTS idx_decisions_ts ON decisions(timestamp);
      CREATE INDEX IF NOT EXISTS idx_decisions_agent ON decisions(agent_jti);
      CREATE INDEX IF NOT EXISTS idx_decisions_decision ON decisions(decision);
    `);
  }

  private migrate(): void {
    // Migration: rename `role` column to `mandate_summary` if DB was created with old schema
    const columns = this.db.prepare(`PRAGMA table_info(ovids)`).all() as { name: string }[];
    const hasRole = columns.some(c => c.name === 'role');
    const hasMandate = columns.some(c => c.name === 'mandate_summary');
    if (hasRole && !hasMandate) {
      this.db.exec(`ALTER TABLE ovids RENAME COLUMN role TO mandate_summary`);
    }
  }

  recordIssuance(claims: {
    jti: string; iss: string; mandate_summary: string; parent_chain: string[];
    iat: number; exp: number; raw_jwt?: string;
  }): void {
    const depth = claims.parent_chain.length;
    this.db.prepare(`
      INSERT OR REPLACE INTO ovids (jti, mandate_summary, issuer, parent_chain, issued_at, expires_at, raw_jwt, depth)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(claims.jti, claims.mandate_summary, claims.iss, JSON.stringify(claims.parent_chain),
      claims.iat, claims.exp, claims.raw_jwt ?? '', depth);

    // Insert chain relationships
    if (claims.parent_chain.length > 0) {
      const parentJti = claims.parent_chain[claims.parent_chain.length - 1];
      this.db.prepare(`INSERT OR IGNORE INTO chains (parent_jti, child_jti) VALUES (?, ?)`)
        .run(parentJti, claims.jti);
    }
  }

  recordDecision(agentJti: string, action: string, resource: string, decision: string, policies?: string[]): void {
    this.db.prepare(`
      INSERT INTO decisions (timestamp, agent_jti, action, resource, decision, determining_policies)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(Math.floor(Date.now() / 1000), agentJti, action, resource, decision,
      JSON.stringify(policies ?? []));
  }

  recordDecisionAt(timestamp: number, agentJti: string, action: string, resource: string, decision: string, policies?: string[]): void {
    this.db.prepare(`
      INSERT INTO decisions (timestamp, agent_jti, action, resource, decision, determining_policies)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(timestamp, agentJti, action, resource, decision, JSON.stringify(policies ?? []));
  }

  importJsonl(logPath: string): { imported: number } {
    const lines = readFileSync(logPath, 'utf-8').trim().split('\n').filter(l => l.length > 0);
    let imported = 0;
    const insertOvid = this.db.prepare(`INSERT OR IGNORE INTO ovids (jti, mandate_summary, issuer, parent_chain, issued_at, expires_at, raw_jwt, depth) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
    const insertChain = this.db.prepare(`INSERT OR IGNORE INTO chains (parent_jti, child_jti) VALUES (?, ?)`);
    const insertDecision = this.db.prepare(`INSERT INTO decisions (timestamp, agent_jti, action, resource, decision, determining_policies) VALUES (?, ?, ?, ?, ?, ?)`);

    const tx = this.db.transaction(() => {
      for (const line of lines) {
        const entry = JSON.parse(line);
        if (entry.event === 'issuance') {
          const chain: string[] = entry.parent_chain ?? [];
          insertOvid.run(entry.jti ?? entry.sub, entry.mandate_summary ?? entry.role ?? '', entry.iss ?? '',
            JSON.stringify(chain), Math.floor(new Date(entry.ts).getTime() / 1000),
            entry.exp ?? 0, '', chain.length);
          if (chain.length > 0) {
            insertChain.run(chain[chain.length - 1], entry.jti ?? entry.sub);
          }
          imported++;
        } else if (entry.event === 'decision') {
          // Ensure agent exists in ovids (might not if log is partial)
          insertOvid.run(entry.agentJti, '', '', '[]', 0, 0, '', 0);
          insertDecision.run(Math.floor(new Date(entry.ts).getTime() / 1000),
            entry.agentJti, entry.action ?? '', entry.resource ?? '',
            entry.decision ?? '', JSON.stringify(entry.policies ?? []));
          imported++;
        }
      }
    });
    tx();
    return { imported };
  }

  private timeWhere(from?: number, to?: number, col = 'timestamp'): { clause: string; params: unknown[] } {
    const parts: string[] = [];
    const params: unknown[] = [];
    if (from != null) { parts.push(`${col} >= ?`); params.push(from); }
    if (to != null) { parts.push(`${col} <= ?`); params.push(to); }
    return { clause: parts.length ? ' AND ' + parts.join(' AND ') : '', params };
  }

  getAgentHistory(jti: string, from?: number, to?: number): unknown[] {
    const tw = this.timeWhere(from, to);
    return this.db.prepare(`SELECT * FROM decisions WHERE agent_jti = ?${tw.clause} ORDER BY timestamp DESC`)
      .all(jti, ...tw.params);
  }

  getAgentTree(rootJti: string): unknown[] {
    return this.db.prepare(`
      WITH RECURSIVE tree(jti, depth) AS (
        SELECT ?, 0
        UNION ALL
        SELECT c.child_jti, tree.depth + 1 FROM chains c JOIN tree ON c.parent_jti = tree.jti
      )
      SELECT t.jti, t.depth, o.mandate_summary, o.issuer, o.issued_at, o.expires_at,
        (SELECT COUNT(*) FROM decisions d WHERE d.agent_jti = t.jti) as decision_count
      FROM tree t LEFT JOIN ovids o ON t.jti = o.jti
    `).all(rootJti);
  }

  getActiveAgents(from?: number, to?: number): unknown[] {
    const tw = this.timeWhere(from, to);
    return this.db.prepare(`
      SELECT d.agent_jti, o.mandate_summary, o.depth, COUNT(*) as decision_count,
        MAX(d.timestamp) as last_active,
        SUM(CASE WHEN d.decision = 'deny' THEN 1 ELSE 0 END) as deny_count,
        SUM(CASE WHEN d.decision = 'allow-proven' THEN 1 ELSE 0 END) as proven_count,
        SUM(CASE WHEN d.decision = 'allow-unproven' THEN 1 ELSE 0 END) as unproven_count
      FROM decisions d LEFT JOIN ovids o ON d.agent_jti = o.jti
      WHERE 1=1${tw.clause}
      GROUP BY d.agent_jti ORDER BY decision_count DESC
    `).all(...tw.params);
  }

  getDecisionBreakdown(from?: number, to?: number): unknown[] {
    const tw = this.timeWhere(from, to);
    return this.db.prepare(`SELECT decision, COUNT(*) as count FROM decisions WHERE 1=1${tw.clause} GROUP BY decision`)
      .all(...tw.params);
  }

  getActionBreakdown(from?: number, to?: number): unknown[] {
    const tw = this.timeWhere(from, to);
    return this.db.prepare(`SELECT action, COUNT(*) as count FROM decisions WHERE 1=1${tw.clause} GROUP BY action ORDER BY count DESC`)
      .all(...tw.params);
  }

  getTopAgents(from?: number, to?: number, limit = 20): unknown[] {
    const tw = this.timeWhere(from, to);
    return this.db.prepare(`
      SELECT d.agent_jti, o.mandate_summary, o.depth, COUNT(*) as decision_count, MAX(d.timestamp) as last_active
      FROM decisions d LEFT JOIN ovids o ON d.agent_jti = o.jti
      WHERE 1=1${tw.clause}
      GROUP BY d.agent_jti ORDER BY decision_count DESC LIMIT ?
    `).all(...tw.params, limit);
  }

  getPolicyUsage(from?: number, to?: number): unknown[] {
    const tw = this.timeWhere(from, to);
    const rows = this.db.prepare(`SELECT determining_policies, decision FROM decisions WHERE 1=1${tw.clause}`)
      .all(...tw.params) as { determining_policies: string; decision: string }[];
    const usage = new Map<string, { count: number; decisions: Map<string, number> }>();
    for (const row of rows) {
      const policies: string[] = JSON.parse(row.determining_policies);
      for (const p of policies) {
        if (!usage.has(p)) usage.set(p, { count: 0, decisions: new Map() });
        const u = usage.get(p)!;
        u.count++;
        u.decisions.set(row.decision, (u.decisions.get(row.decision) ?? 0) + 1);
      }
    }
    return [...usage.entries()]
      .map(([policy, data]) => ({
        policy,
        count: data.count,
        decisions: Object.fromEntries(data.decisions),
      }))
      .sort((a, b) => b.count - a.count);
  }

  getHourlyActivity(from?: number, to?: number): unknown[] {
    const tw = this.timeWhere(from, to);
    return this.db.prepare(`
      SELECT (timestamp / 3600) * 3600 as hour,
        SUM(CASE WHEN decision = 'allow-proven' THEN 1 ELSE 0 END) as proven,
        SUM(CASE WHEN decision = 'allow-unproven' THEN 1 ELSE 0 END) as unproven,
        SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END) as deny,
        COUNT(*) as total
      FROM decisions WHERE 1=1${tw.clause}
      GROUP BY hour ORDER BY hour
    `).all(...tw.params);
  }

  getSpawnRate(from?: number, to?: number): unknown[] {
    const tw = this.timeWhere(from, to, 'issued_at');
    return this.db.prepare(`
      SELECT (issued_at / 3600) * 3600 as hour, COUNT(*) as count
      FROM ovids WHERE issued_at > 0${tw.clause}
      GROUP BY hour ORDER BY hour
    `).all(...tw.params);
  }

  getAnomalies(from?: number, to?: number): { unproven: unknown[]; deepChains: unknown[]; rapidSpawning: unknown[] } {
    const tw = this.timeWhere(from, to);
    const twIssued = this.timeWhere(from, to, 'issued_at');

    const unproven = this.db.prepare(`
      SELECT * FROM decisions WHERE decision = 'allow-unproven'${tw.clause} ORDER BY timestamp DESC LIMIT 100
    `).all(...tw.params);

    const deepChains = this.db.prepare(`
      SELECT * FROM ovids WHERE depth > 3${twIssued.clause}
    `).all(...twIssued.params);

    const rapidSpawning = this.db.prepare(`
      SELECT (issued_at / 60) * 60 as minute, COUNT(*) as count
      FROM ovids WHERE issued_at > 0${twIssued.clause}
      GROUP BY minute HAVING count > 10 ORDER BY minute DESC
    `).all(...twIssued.params);

    return { unproven, deepChains, rapidSpawning };
  }

  getMandateBreakdown(from?: number, to?: number): unknown[] {
    const tw = this.timeWhere(from, to);
    return this.db.prepare(`
      SELECT o.mandate_summary, d.decision, COUNT(*) as count
      FROM decisions d LEFT JOIN ovids o ON d.agent_jti = o.jti
      WHERE 1=1${tw.clause}
      GROUP BY o.mandate_summary, d.decision ORDER BY count DESC
    `).all(...tw.params);
  }

  getMandateActivity(from?: number, to?: number): unknown[] {
    const tw = this.timeWhere(from, to);
    return this.db.prepare(`
      SELECT o.mandate_summary,
        COUNT(DISTINCT d.agent_jti) as agent_count,
        COUNT(*) as decision_count,
        SUM(CASE WHEN d.decision = 'deny' THEN 1 ELSE 0 END) as deny_count,
        SUM(CASE WHEN d.decision = 'allow-proven' THEN 1 ELSE 0 END) as proven_count,
        SUM(CASE WHEN d.decision = 'allow-unproven' THEN 1 ELSE 0 END) as unproven_count,
        MIN(d.timestamp) as first_seen,
        MAX(d.timestamp) as last_seen
      FROM decisions d LEFT JOIN ovids o ON d.agent_jti = o.jti
      WHERE 1=1${tw.clause}
      GROUP BY o.mandate_summary ORDER BY decision_count DESC
    `).all(...tw.params);
  }

  getMandateTimeline(from?: number, to?: number): unknown[] {
    const tw = this.timeWhere(from, to);
    return this.db.prepare(`
      SELECT (d.timestamp / 3600) * 3600 as hour, o.mandate_summary, COUNT(*) as count
      FROM decisions d LEFT JOIN ovids o ON d.agent_jti = o.jti
      WHERE 1=1${tw.clause}
      GROUP BY hour, o.mandate_summary ORDER BY hour
    `).all(...tw.params);
  }

  getMandateActions(mandate: string, from?: number, to?: number): unknown[] {
    const tw = this.timeWhere(from, to);
    return this.db.prepare(`
      SELECT d.action, d.decision, COUNT(*) as count
      FROM decisions d LEFT JOIN ovids o ON d.agent_jti = o.jti
      WHERE o.mandate_summary = ?${tw.clause}
      GROUP BY d.action, d.decision ORDER BY count DESC
    `).all(mandate, ...tw.params);
  }

  // Deprecated aliases
  getRoleBreakdown(from?: number, to?: number): unknown[] { return this.getMandateBreakdown(from, to); }
  getRoleActivity(from?: number, to?: number): unknown[] { return this.getMandateActivity(from, to); }
  getRoleTimeline(from?: number, to?: number): unknown[] { return this.getMandateTimeline(from, to); }
  getRoleActions(role: string, from?: number, to?: number): unknown[] { return this.getMandateActions(role, from, to); }

  getDecisionsByDepth(from?: number, to?: number): unknown[] {
    const tw = this.timeWhere(from, to);
    return this.db.prepare(`
      SELECT o.depth, d.decision, COUNT(*) as count
      FROM decisions d LEFT JOIN ovids o ON d.agent_jti = o.jti
      WHERE 1=1${tw.clause}
      GROUP BY o.depth, d.decision ORDER BY o.depth
    `).all(...tw.params);
  }

  getDecisions(opts: { page?: number; limit?: number; agent?: string; action?: string; decision?: string; from?: number; to?: number }): unknown[] {
    const page = opts.page ?? 1;
    const limit = opts.limit ?? 50;
    const parts: string[] = ['1=1'];
    const params: unknown[] = [];
    if (opts.agent) { parts.push('d.agent_jti = ?'); params.push(opts.agent); }
    if (opts.action) { parts.push('d.action = ?'); params.push(opts.action); }
    if (opts.decision) { parts.push('d.decision = ?'); params.push(opts.decision); }
    if (opts.from != null) { parts.push('d.timestamp >= ?'); params.push(opts.from); }
    if (opts.to != null) { parts.push('d.timestamp <= ?'); params.push(opts.to); }
    return this.db.prepare(`
      SELECT d.*, o.mandate_summary FROM decisions d LEFT JOIN ovids o ON d.agent_jti = o.jti
      WHERE ${parts.join(' AND ')} ORDER BY d.timestamp DESC LIMIT ? OFFSET ?
    `).all(...params, limit, (page - 1) * limit);
  }

  getAgent(jti: string): unknown {
    return this.db.prepare(`SELECT * FROM ovids WHERE jti = ?`).get(jti);
  }

  getOverview(from?: number, to?: number): unknown {
    const tw = this.timeWhere(from, to);
    const totalAgents = (this.db.prepare(`SELECT COUNT(DISTINCT agent_jti) as c FROM decisions WHERE 1=1${tw.clause}`).get(...tw.params) as any)?.c ?? 0;
    const breakdown = this.getDecisionBreakdown(from, to) as { decision: string; count: number }[];
    const total = breakdown.reduce((s, r) => s + r.count, 0);
    const anomalies = this.getAnomalies(from, to);
    const anomalyCount = anomalies.unproven.length + anomalies.deepChains.length + anomalies.rapidSpawning.length;
    return { totalAgents, totalDecisions: total, breakdown, anomalyCount };
  }

  getSankeyData(from?: number, to?: number): unknown {
    const tw = this.timeWhere(from, to);
    const rows = this.db.prepare(`
      SELECT d.agent_jti, o.issuer, o.mandate_summary, d.action, d.decision, COUNT(*) as count
      FROM decisions d LEFT JOIN ovids o ON d.agent_jti = o.jti
      WHERE 1=1${tw.clause}
      GROUP BY d.agent_jti, d.action, d.decision
    `).all(...tw.params) as any[];

    const nodeNames: string[] = [];
    const nodeIndex = (name: string) => {
      let idx = nodeNames.indexOf(name);
      if (idx === -1) { idx = nodeNames.length; nodeNames.push(name); }
      return idx;
    };
    const linkMap = new Map<string, number>();
    const addLink = (s: number, t: number, v: number) => {
      const k = `${s}-${t}`;
      linkMap.set(k, (linkMap.get(k) ?? 0) + v);
    };

    for (const r of rows) {
      const issuer = r.issuer || 'unknown';
      const agent = r.agent_jti;
      addLink(nodeIndex(issuer), nodeIndex(agent), r.count);
      addLink(nodeIndex(agent), nodeIndex(r.decision), r.count);
      if (r.action) addLink(nodeIndex(agent), nodeIndex(`action:${r.action}`), r.count);
    }

    const links = [...linkMap.entries()].map(([k, v]) => {
      const [s, t] = k.split('-').map(Number);
      return { source: s, target: t, value: v };
    });

    return { nodes: nodeNames.map(name => ({ name })), links };
  }

  close(): void {
    this.db.close();
  }
}
