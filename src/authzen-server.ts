/**
 * AuthZEN PDP API Server
 *
 * Implements the OpenID AuthZEN Authorization API 1.0:
 *   POST /access/v1/evaluation   — single decision
 *   POST /access/v1/evaluations  — batch decisions
 *   GET  /                       — server info
 *
 * Spec: https://openid.github.io/authzen/
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from 'node:http';
import type { OvidConfig } from './config.js';
import type { AuthorizationDetail } from '@clawdreyhepburn/ovid';
import { MandateEngine } from './mandate-engine.js';
import {
  authzenToEvaluateRequest,
  evaluateResultToAuthzen,
  validateAuthZenRequest,
  type AuthZenRequest,
  type AuthZenResponse,
  type AuthZenBatchRequest,
  type AuthZenBatchResponse,
} from './authzen.js';

export interface AuthZenServerConfig {
  port?: number;
  defaultPolicy?: string;
  ovidConfig?: Partial<OvidConfig>;
}

export class AuthZenServer {
  private server: Server | null = null;
  private engine: MandateEngine;
  private defaultPolicy?: string;
  private port: number;

  constructor(config?: AuthZenServerConfig) {
    this.engine = new MandateEngine(config?.ovidConfig);
    this.defaultPolicy = config?.defaultPolicy;
    this.port = config?.port ?? 19832;
  }

  async start(port?: number): Promise<void> {
    const p = port ?? this.port;
    this.server = createServer((req, res) => this.handle(req, res));
    return new Promise((resolve) => {
      this.server!.listen(p, () => {
        const addr = this.server!.address();
        const actualPort = typeof addr === 'object' && addr ? addr.port : p;
        console.log(`OVID AuthZEN PDP: http://localhost:${actualPort}`);
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    if (this.server) {
      return new Promise((resolve) => {
        this.server!.close(() => resolve());
      });
    }
  }

  private handle(req: IncomingMessage, res: ServerResponse): void {
    const url = new URL(req.url || '/', `http://localhost`);
    const path = url.pathname;

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    if (path === '/' && req.method === 'GET') {
      this.json(res, 200, {
        implementation: 'OVID-ME AuthZEN PDP',
        version: '0.2.0',
        spec_version: '1.0',
        cedar_engine: 'cedarling-wasm',
      });
      return;
    }

    if (path === '/access/v1/evaluation') {
      if (req.method === 'GET') {
        res.writeHead(405, { Allow: 'POST' });
        res.end(JSON.stringify({ error: 'Method not allowed. Use POST.' }));
        return;
      }
      if (req.method === 'POST') {
        this.readBody(req, (err, body) => {
          if (err) { this.json(res, 400, { error: 'Invalid JSON' }); return; }
          this.handleEvaluation(body, res);
        });
        return;
      }
    }

    if (path === '/access/v1/evaluations' && req.method === 'POST') {
      this.readBody(req, (err, body) => {
        if (err) { this.json(res, 400, { error: 'Invalid JSON' }); return; }
        this.handleBatchEvaluation(body, res);
      });
      return;
    }

    res.writeHead(404);
    res.end(JSON.stringify({ error: 'Not found' }));
  }

  private async handleEvaluation(body: unknown, res: ServerResponse): Promise<void> {
    if (!validateAuthZenRequest(body)) {
      this.json(res, 400, { error: 'Invalid AuthZEN request: missing required fields (subject.type, subject.id, action.name, resource.type, resource.id)' });
      return;
    }

    try {
      const mandate = this.resolveMandate(body);
      if (!mandate) {
        this.json(res, 400, { error: 'No mandate available: provide context.authorization_details, context.ovid_token, or configure a default policy' });
        return;
      }

      const { agentJti, request } = authzenToEvaluateRequest(body);
      const result = await this.engine.evaluate(agentJti, mandate, request);
      const response = evaluateResultToAuthzen(result);
      this.json(res, 200, response);
    } catch (e: any) {
      this.json(res, 500, { error: e.message });
    }
  }

  private async handleBatchEvaluation(body: unknown, res: ServerResponse): Promise<void> {
    if (!body || typeof body !== 'object' || !Array.isArray((body as any).evaluations)) {
      this.json(res, 400, { error: 'Invalid batch request: expected { evaluations: [...] }' });
      return;
    }

    const batch = body as AuthZenBatchRequest;
    const results: AuthZenResponse[] = [];

    for (const req of batch.evaluations) {
      if (!validateAuthZenRequest(req)) {
        results.push({ decision: false, context: { reason_admin: { en: 'Invalid request format' } } });
        continue;
      }

      try {
        const mandate = this.resolveMandate(req);
        if (!mandate) {
          results.push({ decision: false, context: { reason_admin: { en: 'No mandate available' } } });
          continue;
        }

        const { agentJti, request } = authzenToEvaluateRequest(req);
        const result = await this.engine.evaluate(agentJti, mandate, request);
        results.push(evaluateResultToAuthzen(result));
      } catch (e: any) {
        results.push({ decision: false, context: { reason_admin: { en: `Error: ${e.message}` } } });
      }
    }

    this.json(res, 200, { evaluations: results } satisfies AuthZenBatchResponse);
  }

  private resolveMandate(req: AuthZenRequest): AuthorizationDetail | undefined {
    // 1. Inline authorization_details in context
    if (req.context?.authorization_details) {
      const ad = req.context.authorization_details as any;
      return {
        type: ad.type || 'agent_mandate',
        rarFormat: ad.rarFormat || 'cedar',
        policySet: ad.policySet || '',
      } as AuthorizationDetail;
    }

    // 2. TODO: Token mode (context.ovid_token) — verify JWT, extract mandate
    // Not implemented yet; would need token verification infrastructure.

    // 3. Default policy
    if (this.defaultPolicy) {
      return {
        type: 'agent_mandate',
        rarFormat: 'cedar' as const,
        policySet: this.defaultPolicy,
      } as AuthorizationDetail;
    }

    return undefined;
  }

  private readBody(req: IncomingMessage, cb: (err: Error | null, body: unknown) => void): void {
    let data = '';
    req.on('data', (chunk: Buffer) => { data += chunk.toString(); });
    req.on('end', () => {
      try {
        cb(null, JSON.parse(data));
      } catch (e: any) {
        cb(e, null);
      }
    });
  }

  private json(res: ServerResponse, status: number, data: unknown): void {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
  }
}
