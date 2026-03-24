/**
 * Mandate engine: wraps the evaluator with modes (enforce/dry-run/shadow)
 * and subset proof verification.
 */

import type { AuthorizationDetail, OvidClaims } from '@clawdreyhepburn/ovid';
type CedarMandate = AuthorizationDetail;

/** Extract the first agent_mandate entry from an OvidClaims token */
export function extractMandate(claims: OvidClaims): AuthorizationDetail {
  const detail = claims.authorization_details?.find(d => d.type === 'agent_mandate');
  return detail ?? claims.authorization_details?.[0] ?? { type: 'agent_mandate', rarFormat: 'cedar' as const, policySet: '' };
}
import type { OvidConfig } from './config.js';
import type { EvaluateRequest, EvaluateResult } from './evaluate.js';
import { evaluateMandate, evaluateMandateAsync } from './evaluate.js';
import { resolveConfig } from './config.js';
import { AuditLogger } from './audit.js';
import { proveSubset, proverBinaryExists } from './subset-prover.js';

export class MandateEngine {
  private config: OvidConfig;
  private logger: AuditLogger;

  constructor(config?: Partial<OvidConfig>) {
    this.config = resolveConfig(config);
    this.logger = new AuditLogger(this.config.auditLog ?? undefined);
  }

  async evaluate(
    agentJti: string,
    mandate: CedarMandate,
    request: EvaluateRequest,
  ): Promise<EvaluateResult> {
    const mode = this.config.mandateMode;
    const cedarText = mandate.policySet;
    const engine = this.config.engine;

    // Evaluate the real mandate — use async WASM-aware evaluator
    const real = engine === 'fallback'
      ? evaluateMandate(cedarText, request)
      : await evaluateMandateAsync(cedarText, agentJti, request, engine);

    let result: EvaluateResult;

    switch (mode) {
      case 'enforce':
        result = { decision: real.decision, mode, matchedPolicy: real.matchedPolicy, reason: real.reason };
        break;

      case 'dry-run':
        // Evaluate but always allow
        result = {
          decision: 'allow',
          mode,
          matchedPolicy: real.matchedPolicy,
          reason: real.decision === 'deny'
            ? `dry-run: would deny (${real.reason})`
            : real.reason,
        };
        break;

      case 'shadow': {
        // Evaluate shadow mandate if configured
        let shadowDecision: 'allow' | 'deny' | undefined;
        if (this.config.shadowMandate) {
          const shadow = evaluateMandate(this.config.shadowMandate.policySet, request);
          shadowDecision = shadow.decision;
        }
        result = {
          decision: real.decision,
          mode,
          shadowDecision,
          matchedPolicy: real.matchedPolicy,
          reason: real.reason,
        };
        break;
      }
    }

    // Audit log every evaluation
    this.logger.logDecision(
      agentJti,
      request.action,
      request.resource,
      result.decision,
      result.matchedPolicy ? [result.matchedPolicy] : undefined,
    );

    return result;
  }

  async verifySubset(
    mandate: CedarMandate,
    parentPrincipal: string,
  ): Promise<{ proven: boolean; reason?: string }> {
    if (this.config.subsetProof === 'off') {
      return { proven: true };
    }

    if (!this.config.policySource) {
      return { proven: false, reason: 'no policy source configured' };
    }

    const parentPolicy = await this.config.policySource.getEffectivePolicy(parentPrincipal);
    if (!parentPolicy) {
      return { proven: false, reason: `no effective policy for principal: ${parentPrincipal}` };
    }

    const childText = mandate.policySet.trim();

    // Try SMT prover first if binary exists
    if (proverBinaryExists()) {
      const proofResult = await proveSubset(parentPolicy, childText, {
        timeoutMs: this.config.proofTimeoutMs,
      });
      if (proofResult.proven) {
        return { proven: true };
      }
      // If prover ran but couldn't prove, fall through to structural comparison
      // (prover might not support --parent/--child args yet)
    }

    // Structural comparison fallback: exact substring match
    if (parentPolicy.includes(childText)) {
      return { proven: true };
    }

    return {
      proven: false,
      reason: 'structural subset proof inconclusive',
    };
  }
}
