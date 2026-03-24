import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { authzenToEvaluateRequest, evaluateResultToAuthzen, validateAuthZenRequest } from '../src/authzen.js';
import { AuthZenServer } from '../src/authzen-server.js';
import type { EvaluateResult } from '../src/evaluate.js';

// ── Adapter Tests ───────────────────────────────────────────────

describe('AuthZEN Adapters', () => {
  describe('authzenToEvaluateRequest', () => {
    it('maps subject.id to agentJti', () => {
      const result = authzenToEvaluateRequest({
        subject: { type: 'agent', id: 'agent-47' },
        action: { name: 'read_file' },
        resource: { type: 'file', id: '/src/index.ts' },
      });
      expect(result.agentJti).toBe('agent-47');
      expect(result.request.action).toBe('read_file');
      expect(result.request.resource).toBe('/src/index.ts');
    });

    it('passes context through', () => {
      const result = authzenToEvaluateRequest({
        subject: { type: 'agent', id: 'a1' },
        action: { name: 'exec' },
        resource: { type: 'command', id: 'ls' },
        context: { env: 'prod' },
      });
      expect(result.request.context).toEqual({ env: 'prod' });
    });
  });

  describe('evaluateResultToAuthzen', () => {
    it('converts allow to decision: true', () => {
      const result: EvaluateResult = { decision: 'allow', mode: 'enforce' };
      const response = evaluateResultToAuthzen(result);
      expect(response.decision).toBe(true);
      expect(response.context?.reason_admin?.en).toBe('Permitted by mandate');
    });

    it('converts deny to decision: false', () => {
      const result: EvaluateResult = { decision: 'deny', mode: 'enforce', reason: 'explicit forbid' };
      const response = evaluateResultToAuthzen(result);
      expect(response.decision).toBe(false);
      expect(response.context?.reason_admin?.en).toBe('explicit forbid');
    });

    it('uses default deny reason when none provided', () => {
      const result: EvaluateResult = { decision: 'deny', mode: 'enforce' };
      const response = evaluateResultToAuthzen(result);
      expect(response.decision).toBe(false);
      expect(response.context?.reason_admin?.en).toBe('Denied by mandate');
    });
  });

  describe('validateAuthZenRequest', () => {
    it('accepts valid request', () => {
      expect(validateAuthZenRequest({
        subject: { type: 'agent', id: 'a1' },
        action: { name: 'read' },
        resource: { type: 'file', id: '/x' },
      })).toBe(true);
    });

    it('rejects null', () => { expect(validateAuthZenRequest(null)).toBe(false); });
    it('rejects missing subject', () => {
      expect(validateAuthZenRequest({ action: { name: 'x' }, resource: { type: 'f', id: '/' } })).toBe(false);
    });
    it('rejects missing action.name', () => {
      expect(validateAuthZenRequest({ subject: { type: 'a', id: '1' }, action: {}, resource: { type: 'f', id: '/' } })).toBe(false);
    });
  });
});

// ── Server Tests ────────────────────────────────────────────────

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

async function get(port: number, path: string): Promise<{ status: number; body: any; headers: Headers }> {
  const res = await fetch(`http://localhost:${port}${path}`);
  const text = await res.text();
  let body: any;
  try { body = JSON.parse(text); } catch { body = text; }
  return { status: res.status, body, headers: res.headers };
}

describe('AuthZEN Server - Permit Policy', () => {
  let server: AuthZenServer;
  let port: number;

  beforeAll(async () => {
    server = new AuthZenServer({
      port: 0,
      defaultPolicy: 'permit(principal, action == Ovid::Action::"read_file", resource);',
      ovidConfig: { mandateMode: 'enforce', engine: 'fallback' },
    });
    await server.start();
    port = (server as any).server.address().port;
  });

  afterAll(async () => { await server.stop(); });

  it('GET / returns server info', async () => {
    const { status, body } = await get(port, '/');
    expect(status).toBe(200);
    expect(body.implementation).toBe('OVID-ME AuthZEN PDP');
    expect(body.version).toBe('0.2.0');
    expect(body.spec_version).toBe('1.0');
  });

  it('GET /access/v1/evaluation returns 405', async () => {
    const { status } = await get(port, '/access/v1/evaluation');
    expect(status).toBe(405);
  });

  it('POST /access/v1/evaluation with matching action returns decision: true', async () => {
    const { status, body } = await post(port, '/access/v1/evaluation', {
      subject: { type: 'agent', id: 'agent-47' },
      action: { name: 'read_file' },
      resource: { type: 'file', id: '/src/index.ts' },
    });
    expect(status).toBe(200);
    expect(body.decision).toBe(true);
    expect(body.context?.reason_admin?.en).toBeDefined();
  });

  it('POST /access/v1/evaluation with non-matching action returns decision: false', async () => {
    const { status, body } = await post(port, '/access/v1/evaluation', {
      subject: { type: 'agent', id: 'agent-47' },
      action: { name: 'exec' },
      resource: { type: 'command', id: 'rm -rf /' },
    });
    expect(status).toBe(200);
    expect(body.decision).toBe(false);
  });

  it('POST with malformed JSON returns 400', async () => {
    const res = await fetch(`http://localhost:${port}/access/v1/evaluation`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not json',
    });
    expect(res.status).toBe(400);
  });

  it('POST with missing fields returns 400', async () => {
    const { status, body } = await post(port, '/access/v1/evaluation', {
      subject: { type: 'agent' },  // missing id
      action: { name: 'read' },
      resource: { type: 'file', id: '/x' },
    });
    expect(status).toBe(400);
    expect(body.error).toContain('Invalid AuthZEN request');
  });

  it('POST /access/v1/evaluations batch returns array of decisions', async () => {
    const { status, body } = await post(port, '/access/v1/evaluations', {
      evaluations: [
        { subject: { type: 'agent', id: 'a1' }, action: { name: 'read_file' }, resource: { type: 'file', id: '/src/index.ts' } },
        { subject: { type: 'agent', id: 'a1' }, action: { name: 'exec' }, resource: { type: 'command', id: 'rm -rf /' } },
      ],
    });
    expect(status).toBe(200);
    expect(body.evaluations).toHaveLength(2);
    expect(body.evaluations[0].decision).toBe(true);
    expect(body.evaluations[1].decision).toBe(false);
  });

  it('POST with inline authorization_details overrides default policy', async () => {
    const { status, body } = await post(port, '/access/v1/evaluation', {
      subject: { type: 'agent', id: 'a1' },
      action: { name: 'exec' },
      resource: { type: 'command', id: 'deploy' },
      context: {
        authorization_details: {
          type: 'agent_mandate',
          rarFormat: 'cedar',
          policySet: 'permit(principal, action == Ovid::Action::"exec", resource);',
        },
      },
    });
    expect(status).toBe(200);
    expect(body.decision).toBe(true);
  });

  it('returns 404 for unknown paths', async () => {
    const { status } = await get(port, '/unknown');
    expect(status).toBe(404);
  });
});

describe('AuthZEN Server - Deny Policy', () => {
  let server: AuthZenServer;
  let port: number;

  beforeAll(async () => {
    server = new AuthZenServer({
      port: 0,
      defaultPolicy: 'forbid(principal, action, resource);',
      ovidConfig: { mandateMode: 'enforce', engine: 'fallback' },
    });
    await server.start();
    port = (server as any).server.address().port;
  });

  afterAll(async () => { await server.stop(); });

  it('denies all requests with forbid policy', async () => {
    const { status, body } = await post(port, '/access/v1/evaluation', {
      subject: { type: 'agent', id: 'a1' },
      action: { name: 'read_file' },
      resource: { type: 'file', id: '/anything' },
    });
    expect(status).toBe(200);
    expect(body.decision).toBe(false);
  });
});

describe('AuthZEN Server - No Default Policy', () => {
  let server: AuthZenServer;
  let port: number;

  beforeAll(async () => {
    server = new AuthZenServer({
      port: 0,
      ovidConfig: { mandateMode: 'enforce', engine: 'fallback' },
    });
    await server.start();
    port = (server as any).server.address().port;
  });

  afterAll(async () => { await server.stop(); });

  it('returns 400 when no mandate is available', async () => {
    const { status, body } = await post(port, '/access/v1/evaluation', {
      subject: { type: 'agent', id: 'a1' },
      action: { name: 'read' },
      resource: { type: 'file', id: '/x' },
    });
    expect(status).toBe(400);
    expect(body.error).toContain('No mandate available');
  });
});
