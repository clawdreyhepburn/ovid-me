/**
 * Mandate engine: wraps the evaluator with modes (enforce/dry-run/shadow)
 * and subset proof verification.
 */

import type { CedarMandate } from '@clawdreyhepburn/ovid';
import type { OvidConfig } from './config.js';
import type { EvaluateRequest, EvaluateResult } from './evaluate.js';
import { evaluateMandate } from './evaluate.js';
import { resolveConfig } from './config.js';
import { AuditLogger } from './audit.js';

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

    // Evaluate the real mandate
    const real = evaluateMandate(cedarText, request);

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

    // Basic structural comparison stub.
    // Real SMT-based subset proof (via cvc5) is future work.
    // For now: if the child mandate text is a substring of the parent policy,
    // consider it proven (very conservative — only exact reuse passes).
    const childText = mandate.policySet.trim();
    if (parentPolicy.includes(childText)) {
      return { proven: true };
    }

    return {
      proven: false,
      reason: 'structural subset proof inconclusive (SMT prover not yet implemented)',
    };
  }
}
