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
import { exactMatch, normalizedMatch } from './subset-structural.js';

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

  /**
   * Verify that `mandate.policySet` is a subset of `parentPrincipal`'s
   * effective policy at this moment in time.
   *
   * Proof strategy, in order:
   *   1. SMT prover (`agent-authz-prover`): sound and complete for the
   *      Cedar fragments it supports.
   *   2. Structural fallback, iff `config.structuralFallback !== 'off'`:
   *      reflexive-only check (exact or normalized). Sound but incomplete.
   *   3. Otherwise: return `proven: false` with a descriptive reason.
   *      **Fail closed.** We do NOT use `String.includes` or any other
   *      substring heuristic; those are unsound as subset proofs.
   *
   * The returned `method` field names which strategy succeeded (or failed),
   * so callers and auditors can tell SMT-proven subsets apart from
   * reflexive-only matches.
   */
  async verifySubset(
    mandate: CedarMandate,
    parentPrincipal: string,
  ): Promise<{
    proven: boolean;
    reason?: string;
    method?: 'smt' | 'structural-exact' | 'structural-normalized' | 'none';
  }> {
    if (this.config.subsetProof === 'off') {
      return { proven: true, method: 'none' };
    }

    if (!this.config.policySource) {
      return { proven: false, reason: 'no policy source configured', method: 'none' };
    }

    const parentPolicy = await this.config.policySource.getEffectivePolicy(parentPrincipal);
    if (parentPolicy === null) {
      return {
        proven: false,
        reason: `no effective policy for principal: ${parentPrincipal}`,
        method: 'none',
      };
    }

    const childText = mandate.policySet;

    // 1. SMT prover (sound + complete within its supported fragment).
    let smtInconclusiveReason: string | undefined;
    if (proverBinaryExists()) {
      const proofResult = await proveSubset(parentPolicy, childText, {
        timeoutMs: this.config.proofTimeoutMs,
      });
      if (proofResult.proven) {
        return { proven: true, method: 'smt' };
      }
      smtInconclusiveReason = proofResult.reason;
    } else {
      smtInconclusiveReason = 'prover binary not found';
    }

    // 2. Structural fallback (reflexive-only, sound but very limited).
    switch (this.config.structuralFallback) {
      case 'exact':
        if (exactMatch(parentPolicy, childText)) {
          return { proven: true, method: 'structural-exact' };
        }
        break;
      case 'normalized':
        if (normalizedMatch(parentPolicy, childText)) {
          return { proven: true, method: 'structural-normalized' };
        }
        break;
      case 'off':
        // No fallback permitted; SMT result (or its absence) is final.
        break;
    }

    // 3. Fail closed. The child policy is NOT provably a subset.
    const base = smtInconclusiveReason
      ? `SMT prover inconclusive (${smtInconclusiveReason})`
      : 'SMT prover unavailable';
    const fallbackNote = this.config.structuralFallback === 'off'
      ? '; structural fallback disabled (sound default)'
      : `; reflexive ${this.config.structuralFallback} match also failed`;
    return {
      proven: false,
      reason: base + fallbackNote,
      method: 'none',
    };
  }
}
