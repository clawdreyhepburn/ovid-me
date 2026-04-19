import { createServer, type IncomingMessage, type ServerResponse, type Server } from 'node:http';
import { AuditDatabase } from './audit-db.js';
import { dashboardHtml } from './dashboard-html.js';
import {
  resolveSecurity,
  applyCors,
  verifyAuth,
  announceAuthToken,
  type SecurityConfig,
  type ResolvedSecurity,
} from './server-security.js';

interface DashboardOptions {
  port?: number;
  dbPath?: string;
  security?: SecurityConfig;
}

export class DashboardServer {
  private db: AuditDatabase;
  private server: Server | null = null;
  private port: number;
  private security: ResolvedSecurity;

  constructor(opts?: DashboardOptions) {
    this.port = opts?.port ?? 19831;
    this.db = new AuditDatabase(opts?.dbPath);
    this.security = resolveSecurity(opts?.security);
  }

  /** Expose the effective bearer token (null when auth is disabled). */
  getAuthToken(): string | null { return this.security.token; }

  async start(): Promise<void> {
    this.server = createServer((req, res) => this.handle(req, res));
    return new Promise((resolve) => {
      this.server!.listen(this.port, this.security.bindHost, () => {
        // eslint-disable-next-line no-console
        console.log(`OVID Dashboard: http://${this.security.bindHost}:${this.port}`);
        announceAuthToken('dashboard', this.security);
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

    // CORS (no-op unless explicitly allowlisted in config)
    if (applyCors(req, res, this.security)) return;

    // Bearer-token auth. GET /?token=<t> and Authorization: Bearer are
    // both accepted; the index HTML is also behind auth to prevent
    // drive-by browsing.
    if (!verifyAuth(req, res, this.security)) return;

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
      } else if (route === 'mandates') {
        data = this.db.getMandateActivity(from, to);
      } else if (route === 'mandates/breakdown') {
        data = this.db.getMandateBreakdown(from, to);
      } else if (route === 'mandates/timeline') {
        data = this.db.getMandateTimeline(from, to);
      } else if (route.startsWith('mandates/') && !route.slice(9).includes('/')) {
        const mandate = decodeURIComponent(route.slice(9));
        data = this.db.getMandateActions(mandate, from, to);
      // Deprecated aliases — /api/roles/* → /api/mandates/*
      } else if (route === 'roles') {
        data = this.db.getMandateActivity(from, to);
      } else if (route === 'roles/breakdown') {
        data = this.db.getMandateBreakdown(from, to);
      } else if (route === 'roles/timeline') {
        data = this.db.getMandateTimeline(from, to);
      } else if (route.startsWith('roles/') && !route.slice(6).includes('/')) {
        const role = decodeURIComponent(route.slice(6));
        data = this.db.getMandateActions(role, from, to);
      // NOTE: the previous POST /api/import route was removed. It took a
      // server-local filesystem path from the request body and read it,
      // which was an arbitrary-file-disclosure primitive for anyone who
      // could reach the dashboard. Callers that need to import should
      // use AuditDatabase.importJsonl() programmatically from a process
      // that already has the intended filesystem authority.
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
