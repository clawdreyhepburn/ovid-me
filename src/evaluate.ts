/**
 * Core Cedar mandate evaluator for OVID.
 *
 * String-matching fallback engine that parses Cedar policy text
 * and evaluates against action/resource. Supports a subset of Cedar syntax.
 */

import type { CedarMandate } from '@clawdreyhepburn/ovid'
import type { OvidConfig } from './config.js'

export interface EvaluateRequest {
  action: string
  resource: string
  context?: Record<string, unknown>
}

export interface EvaluateResult {
  decision: 'allow' | 'deny'
  mode: 'enforce' | 'dry-run' | 'shadow'
  shadowDecision?: 'allow' | 'deny'
  matchedPolicy?: string
  reason?: string
}

/** Parsed representation of a single Cedar policy statement */
interface ParsedPolicy {
  effect: 'permit' | 'forbid'
  /** null = any action */
  actions: string[] | null
  /** null = any resource; string = glob pattern from `resource.path like "..."` */
  resourceGlob: string | null
  raw: string
}

/**
 * Parse Cedar policy text into individual policy statements.
 * Supports:
 *   - permit/forbid(principal, action == Ovid::Action::"x", resource)
 *   - permit/forbid(principal, action in [Ovid::Action::"x", ...], resource)
 *   - permit/forbid(principal, action, resource) when { resource.path like "/src/*" }
 *   - permit/forbid(principal, action, resource) — match all
 */
export function parsePolicies(cedarText: string): ParsedPolicy[] {
  const policies: ParsedPolicy[] = []
  // Split on top-level permit/forbid statements
  const stmtRegex = /(permit|forbid)\s*\(([^)]*)\)\s*(?:when\s*\{([^}]*)\})?\s*;/g
  let match
  while ((match = stmtRegex.exec(cedarText)) !== null) {
    const effect = match[1] as 'permit' | 'forbid'
    const head = match[2]
    const whenClause = match[3] ?? ''
    const raw = match[0]

    // Parse actions from head
    let actions: string[] | null = null

    // action == Ovid::Action::"xxx"
    const exactAction = head.match(/action\s*==\s*Ovid::Action::"([^"]+)"/)
    if (exactAction) {
      actions = [exactAction[1]]
    }

    // action in [Ovid::Action::"x", Ovid::Action::"y"]
    const actionList = head.match(/action\s+in\s*\[([^\]]+)\]/)
    if (actionList) {
      const items = actionList[1].matchAll(/Ovid::Action::"([^"]+)"/g)
      actions = [...items].map(m => m[1])
    }

    // Parse resource glob from when clause
    let resourceGlob: string | null = null
    const likeMatch = whenClause.match(/resource\.path\s+like\s+"([^"]+)"/)
    if (likeMatch) {
      resourceGlob = likeMatch[1]
    }

    policies.push({ effect, actions, resourceGlob, raw })
  }
  return policies
}

/**
 * Match a Cedar `like` pattern against a string.
 * Cedar `like` uses `*` as wildcard (matches any sequence of chars).
 */
function matchLike(pattern: string, value: string): boolean {
  // Escape regex special chars except *, then replace * with .*
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')
  return new RegExp(`^${escaped}$`).test(value)
}

function policyMatches(policy: ParsedPolicy, request: EvaluateRequest): boolean {
  // Check action constraint
  if (policy.actions !== null && !policy.actions.includes(request.action)) {
    return false
  }
  // Check resource glob
  if (policy.resourceGlob !== null && !matchLike(policy.resourceGlob, request.resource)) {
    return false
  }
  return true
}

/**
 * Evaluate a mandate's Cedar policies against a request.
 * Cedar semantics: forbid overrides permit; default deny.
 */
export async function evaluateMandate(
  mandate: CedarMandate,
  request: EvaluateRequest,
  config?: Partial<OvidConfig>,
): Promise<EvaluateResult> {
  const mode = config?.mandateMode ?? 'enforce'
  const policyText = mandate.policySet
  const policies = parsePolicies(policyText)

  const result = evaluatePolicies(policies, request, mode)

  // In dry-run mode, log the real decision but always allow
  if (mode === 'dry-run' && result.decision === 'deny') {
    return { ...result, decision: 'allow', mode: 'dry-run' }
  }

  return result
}

/** Core evaluation logic used by both evaluateMandate and MandateEngine */
export function evaluatePolicies(
  policies: ParsedPolicy[],
  request: EvaluateRequest,
  mode: 'enforce' | 'dry-run' | 'shadow' = 'enforce',
): EvaluateResult {
  let matchedPermit: string | undefined
  let matchedForbid: string | undefined

  for (const policy of policies) {
    if (!policyMatches(policy, request)) continue

    if (policy.effect === 'forbid') {
      matchedForbid = policy.raw
    } else if (policy.effect === 'permit' && !matchedPermit) {
      matchedPermit = policy.raw
    }
  }

  // Cedar semantics: any forbid → deny
  if (matchedForbid) {
    return {
      decision: 'deny',
      mode,
      matchedPolicy: matchedForbid,
      reason: 'explicit forbid policy matched',
    }
  }

  if (matchedPermit) {
    return { decision: 'allow', mode, matchedPolicy: matchedPermit }
  }

  // Default deny
  return {
    decision: 'deny',
    mode,
    reason: 'no matching permit policy (default deny)',
  }
}
