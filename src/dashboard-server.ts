import { createServer, type IncomingMessage, type ServerResponse, type Server } from 'node:http';
import { readFileSync } from 'node:fs';
import { AuditDatabase } from './audit-db.js';
import { dashboardHtml } from './dashboard-html.js';

interface DashboardOptions {
  port?: number;
  dbPath?: string;
}

export class DashboardServer {
  private db: AuditDatabase;
  private server: Server | null = null;
  private port: number;

  constructor(opts?: DashboardOptions) {
    this.port = opts?.port ?? 19831;
    this.db = new AuditDatabase(opts?.dbPath);
  }

  async start(): Promise<void> {
    this.server = createServer((req, res) => this.handle(req, res));
    return new Promise((resolve) => {
      this.server!.listen(this.port, () => {
        console.log(`OVID Dashboard: http://localhost:${this.port}`);
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    if (this.server) {
      return new Promise((resolve) => {
        this.server!.close(() => { this.db.close(); resolve(); });
      });
    }
    this.db.close();
  }

  getDatabase(): AuditDatabase { return this.db; }

  private handle(req: IncomingMessage, res: ServerResponse): void {
    const url = new URL(req.url || '/', `http://localhost:${this.port}`);
    const path = url.pathname;
    const from = url.searchParams.get('from') ? parseInt(url.searchParams.get('from')!) : undefined;
    const to = url.searchParams.get('to') ? parseInt(url.searchParams.get('to')!) : undefined;

    res.setHeader('Access-Control-Allow-Origin', '*');

    try {
      if (path === '/' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(dashboardHtml());
        return;
      }

      if (!path.startsWith('/api/')) {
        res.writeHead(404); res.end('Not found'); return;
      }

      // API routes
      const route = path.replace('/api/', '');
      let data: unknown;

      if (route === 'overview') {
        data = this.db.getOverview(from, to);
      } else if (route === 'agents') {
        data = this.db.getActiveAgents(from, to);
      } else if (route.startsWith('agents/') && route.endsWith('/tree')) {
        const jti = decodeURIComponent(route.slice(7, -5));
        data = this.db.getAgentTree(jti);
      } else if (route.startsWith('agents/')) {
        const jti = decodeURIComponent(route.slice(7));
        data = { agent: this.db.getAgent(jti), decisions: this.db.getAgentHistory(jti, from, to) };
      } else if (route === 'decisions') {
        const page = url.searchParams.get('page') ? parseInt(url.searchParams.get('page')!) : 1;
        const limit = url.searchParams.get('limit') ? parseInt(url.searchParams.get('limit')!) : 50;
        const agent = url.searchParams.get('agent') || undefined;
        const action = url.searchParams.get('action') || undefined;
        const decision = url.searchParams.get('decision') || undefined;
        data = this.db.getDecisions({ page, limit, agent, action, decision, from, to });
      } else if (route === 'timeline') {
        data = this.db.getHourlyActivity(from, to);
      } else if (route === 'spawn-rate') {
        data = this.db.getSpawnRate(from, to);
      } else if (route === 'policies') {
        data = this.db.getPolicyUsage(from, to);
      } else if (route === 'actions') {
        data = this.db.getActionBreakdown(from, to);
      } else if (route === 'anomalies') {
        data = this.db.getAnomalies(from, to);
      } else if (route === 'sankey') {
        data = this.db.getSankeyData(from, to);
      } else if (route === 'depth') {
        data = this.db.getDecisionsByDepth(from, to);
      } else if (route === 'roles') {
        data = this.db.getRoleActivity(from, to);
      } else if (route === 'roles/breakdown') {
        data = this.db.getRoleBreakdown(from, to);
      } else if (route === 'roles/timeline') {
        data = this.db.getRoleTimeline(from, to);
      } else if (route.startsWith('roles/') && !route.slice(6).includes('/')) {
        const role = decodeURIComponent(route.slice(6));
        data = this.db.getRoleActions(role, from, to);
      } else if (route === 'import' && req.method === 'POST') {
        // Simple: read body as path to JSONL file
        let body = '';
        req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
        req.on('end', () => {
          try {
            const { path: logPath } = JSON.parse(body);
            const result = this.db.importJsonl(logPath);
            this.json(res, result);
          } catch (e: any) {
            res.writeHead(400); res.end(JSON.stringify({ error: e.message }));
          }
        });
        return;
      } else {
        res.writeHead(404); res.end(JSON.stringify({ error: 'Not found' })); return;
      }

      this.json(res, data);
    } catch (e: any) {
      res.writeHead(500);
      res.end(JSON.stringify({ error: e.message }));
    }
  }

  private json(res: ServerResponse, data: unknown): void {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
  }
}

let _server: DashboardServer | null = null;

export async function startDashboard(options?: DashboardOptions): Promise<DashboardServer> {
  _server = new DashboardServer(options);
  await _server.start();
  return _server;
}

export async function stopDashboard(): Promise<void> {
  if (_server) { await _server.stop(); _server = null; }
}
