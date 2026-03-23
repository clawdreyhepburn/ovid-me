/**
 * Full mandate evaluation engine with mode support (enforce/dry-run/shadow)
 * and subset verification.
 */

import type { CedarMandate } from '@clawdreyhepburn/ovid'
import type { OvidConfig, PolicySource } from './config.js'
import { resolveConfig } from './config.js'
import { AuditLogger, createAuditLogger } from './audit.js'
import { parsePolicies, evaluatePolicies } from './evaluate.js'
import type { EvaluateRequest, EvaluateResult } from './evaluate.js'

export class MandateEngine {
  private config: OvidConfig
  private logger: AuditLogger

  constructor(config?: Partial<OvidConfig>) {
    this.config = resolveConfig(config)
    this.logger = this.config.auditLog
      ? createAuditLogger(this.config.auditLog)
      : new AuditLogger() // no-op if no path
  }

  /**
   * Main evaluation — respects enforce/dry-run/shadow modes.
   */
  async evaluate(
    agentJti: string,
    mandate: CedarMandate,
    request: EvaluateRequest,
  ): Promise<EvaluateResult> {
    const mode = this.config.mandateMode
    const policyText = mandate.policySet
    const policies = parsePolicies(policyText)
    const result = evaluatePolicies(policies, request, mode)

    // Log the decision
    this.logger.logDecision(
      agentJti,
      request.action,
      request.resource,
      result.decision,
      result.matchedPolicy ? [result.matchedPolicy] : undefined,
    )

    if (mode === 'shadow') {
      // Also evaluate shadow mandate if configured
      let shadowDecision: 'allow' | 'deny' | undefined
      if (this.config.shadowMandate) {
        const shadowText = this.config.shadowMandate.cedar_policies.join('\n')
        const shadowPolicies = parsePolicies(shadowText)
        const shadowResult = evaluatePolicies(shadowPolicies, request, 'shadow')
        shadowDecision = shadowResult.decision

        this.logger.logCustom('shadow-evaluation', {
          agentJti,
          action: request.action,
          resource: request.resource,
          realDecision: result.decision,
          shadowDecision,
        })
      }

      return { ...result, mode: 'shadow', shadowDecision }
    }

    if (mode === 'dry-run') {
      // Log real decision but always allow
      if (result.decision === 'deny') {
        this.logger.logCustom('dry-run-would-deny', {
          agentJti,
          action: request.action,
          resource: request.resource,
          reason: result.reason,
        })
      }
      return { ...result, decision: 'allow', mode: 'dry-run' }
    }

    // enforce mode — return as-is
    return result
  }

  /**
   * Issuance-time check: is mandate ⊆ parent's effective policy?
   *
   * NOTE: Real SMT-based subset proving (e.g., via cvc5) is future work.
   * This is a structural comparison stub that checks whether each permit
   * in the mandate can be matched by a permit in the parent's policy.
   */
  async verifySubset(
    mandate: CedarMandate,
    parentPrincipal: string,
  ): Promise<{ proven: boolean; reason?: string }> {
    if (this.config.subsetProof === 'off') {
      return { proven: true }
    }

    if (!this.config.policySource) {
      return { proven: false, reason: 'no policy source configured' }
    }

    const parentPolicy = await this.config.policySource.getEffectivePolicy(parentPrincipal)
    if (parentPolicy === null) {
      return { proven: false, reason: 'no effective policy for principal' }
    }

    // Basic structural comparison:
    // For each permit in the mandate, check if the parent has a permit
    // that covers the same (or broader) action/resource space.
    // This is a best-effort heuristic — NOT a sound proof.
    const mandatePolicies = parsePolicies(mandate.policySet)
    const parentPolicies = parsePolicies(parentPolicy)

    const mandatePermits = mandatePolicies.filter(p => p.effect === 'permit')
    const parentPermits = parentPolicies.filter(p => p.effect === 'permit')

    for (const mp of mandatePermits) {
      const covered = parentPermits.some(pp => {
        // Parent with null actions (any action) covers any mandate action
        if (pp.actions !== null) {
          if (mp.actions === null) return false // mandate allows anything, parent doesn't
          if (!mp.actions.every(a => pp.actions!.includes(a))) return false
        }
        // Parent with null resourceGlob (any resource) covers any mandate resource
        if (pp.resourceGlob !== null) {
          if (mp.resourceGlob === null) return false
          // Simple: exact match only. Real subset would need glob containment.
          if (mp.resourceGlob !== pp.resourceGlob) return false
        }
        return true
      })
      if (!covered) {
        return { proven: false, reason: `mandate permit not covered by parent policy: ${mp.raw}` }
      }
    }

    return { proven: true }
  }
}
