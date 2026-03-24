/**
 * AuthZEN types and adapter functions.
 *
 * Implements the OpenID AuthZEN Authorization API 1.0 request/response types
 * and adapters to convert between AuthZEN and OVID-ME's internal evaluate types.
 *
 * Spec: https://openid.github.io/authzen/
 */

import type { EvaluateRequest, EvaluateResult } from './evaluate.js';

// ── AuthZEN Types ───────────────────────────────────────────────

export interface AuthZenSubject {
  type: string;
  id: string;
  properties?: Record<string, unknown>;
}

export interface AuthZenAction {
  name: string;
  properties?: Record<string, unknown>;
}

export interface AuthZenResource {
  type: string;
  id: string;
  properties?: Record<string, unknown>;
}

export interface AuthZenRequest {
  subject: AuthZenSubject;
  action: AuthZenAction;
  resource: AuthZenResource;
  context?: Record<string, unknown>;
}

export interface AuthZenResponse {
  decision: boolean;
  context?: {
    reason_admin?: Record<string, string>;
    reason_user?: Record<string, string>;
  };
}

export interface AuthZenBatchRequest {
  evaluations: AuthZenRequest[];
}

export interface AuthZenBatchResponse {
  evaluations: AuthZenResponse[];
}

// ── Adapter Functions ───────────────────────────────────────────

/**
 * Convert an AuthZEN evaluation request to OVID-ME's internal format.
 */
export function authzenToEvaluateRequest(req: AuthZenRequest): { agentJti: string; request: EvaluateRequest } {
  return {
    agentJti: req.subject.id,
    request: {
      action: req.action.name,
      resource: req.resource.id,
      context: req.context,
    },
  };
}

/**
 * Convert an OVID-ME EvaluateResult to an AuthZEN response.
 */
export function evaluateResultToAuthzen(result: EvaluateResult): AuthZenResponse {
  return {
    decision: result.decision === 'allow',
    context: {
      reason_admin: {
        en: result.reason || (result.decision === 'allow' ? 'Permitted by mandate' : 'Denied by mandate'),
      },
    },
  };
}

/**
 * Validate that an object has the required AuthZEN request shape.
 */
export function validateAuthZenRequest(obj: unknown): obj is AuthZenRequest {
  if (!obj || typeof obj !== 'object') return false;
  const r = obj as Record<string, unknown>;
  if (!r.subject || typeof r.subject !== 'object') return false;
  if (!r.action || typeof r.action !== 'object') return false;
  if (!r.resource || typeof r.resource !== 'object') return false;
  const s = r.subject as Record<string, unknown>;
  const a = r.action as Record<string, unknown>;
  const res = r.resource as Record<string, unknown>;
  if (typeof s.type !== 'string' || typeof s.id !== 'string') return false;
  if (typeof a.name !== 'string') return false;
  if (typeof res.type !== 'string' || typeof res.id !== 'string') return false;
  return true;
}
