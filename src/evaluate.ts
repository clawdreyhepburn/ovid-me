/**
 * Cedar mandate parser + evaluator for OVID.
 *
 * Parses a subset of Cedar policy syntax and evaluates tool call requests.
 * Uses Cedar semantics: default-deny, forbid overrides permit.
 *
 * Supported patterns:
 *   - permit/forbid(principal, action == Ovid::Action::"x", resource)
 *   - permit/forbid(principal, action in [Ovid::Action::"x", ...], resource)
 *   - permit/forbid(principal, action, resource) when { resource.path like "/src/*" }
 *   - permit/forbid(principal, action, resource) — wildcard
 *
 * NOT supported (yet):
 *   - Nested conditions (unless/when with boolean combinators)
 *   - Principal or resource equality constraints in head
 *   - Context conditions beyond resource.path like "..."
 *   - has operator, .contains(), decimal/IP extensions
 */

export interface EvaluateRequest {
  action: string;
  resource: string;
  context?: Record<string, unknown>;
}

export interface EvaluateResult {
  decision: 'allow' | 'deny';
  mode: 'enforce' | 'dry-run' | 'shadow';
  shadowDecision?: 'allow' | 'deny';
  matchedPolicy?: string;
  reason?: string;
}

interface ParsedPolicy {
  effect: 'permit' | 'forbid';
  actions: string[] | null; // null = wildcard (matches any)
  resourceGlob: string | null; // null = wildcard
  raw: string;
}

/**
 * Parse Cedar policy text into structured policies.
 */
export function parsePolicies(cedarText: string): ParsedPolicy[] {
  const policies: ParsedPolicy[] = [];
  // Split on top-level permit/forbid boundaries
  const blocks = cedarText.match(/(permit|forbid)\s*\([^;]*;/gs);
  if (!blocks) return policies;

  for (const block of blocks) {
    const effect = block.trimStart().startsWith('forbid') ? 'forbid' as const : 'permit' as const;

    // Extract action constraint
    let actions: string[] | null = null;

    // Action list: action in [Ovid::Action::"x", ...]
    const listMatch = block.match(/action\s+in\s*\[([^\]]+)\]/);
    if (listMatch) {
      actions = [...listMatch[1].matchAll(/Ovid::Action::"([^"]+)"/g)].map(m => m[1]);
    } else {
      // Single action: action == Ovid::Action::"x"
      const singleMatch = block.match(/action\s*==\s*Ovid::Action::"([^"]+)"/);
      if (singleMatch) {
        actions = [singleMatch[1]];
      }
      // else: wildcard (action with no constraint)
    }

    // Extract resource glob from when clause
    let resourceGlob: string | null = null;
    const whenMatch = block.match(/when\s*\{\s*resource\.path\s+like\s+"([^"]+)"\s*\}/);
    if (whenMatch) {
      resourceGlob = whenMatch[1];
    }

    policies.push({ effect, actions, resourceGlob, raw: block.trim() });
  }

  return policies;
}

/**
 * Match a Cedar `like` glob pattern against a string.
 * Cedar `like` uses `*` as wildcard (matches any sequence of chars).
 */
function matchGlob(pattern: string, value: string): boolean {
  // Escape regex special chars except *, then replace * with .*
  const re = new RegExp(
    '^' + pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$'
  );
  return re.test(value);
}

function policyMatchesRequest(policy: ParsedPolicy, request: EvaluateRequest): boolean {
  // Check action constraint
  if (policy.actions !== null && !policy.actions.includes(request.action)) {
    return false;
  }
  // Check resource glob
  if (policy.resourceGlob !== null && !matchGlob(policy.resourceGlob, request.resource)) {
    return false;
  }
  return true;
}

/**
 * Evaluate a request against Cedar policy text.
 * Returns allow/deny with Cedar semantics (default-deny, forbid overrides permit).
 */
export function evaluateMandate(
  cedarText: string,
  request: EvaluateRequest,
): { decision: 'allow' | 'deny'; matchedPolicy?: string; reason?: string } {
  const policies = parsePolicies(cedarText);

  if (policies.length === 0) {
    return { decision: 'deny', reason: 'no policies defined' };
  }

  let firstPermit: string | undefined;
  for (const policy of policies) {
    if (!policyMatchesRequest(policy, request)) continue;

    if (policy.effect === 'forbid') {
      return { decision: 'deny', matchedPolicy: policy.raw, reason: 'explicit forbid' };
    }
    if (policy.effect === 'permit' && !firstPermit) {
      firstPermit = policy.raw;
    }
  }

  if (firstPermit) {
    return { decision: 'allow', matchedPolicy: firstPermit };
  }

  return { decision: 'deny', reason: 'no matching permit policy' };
}
