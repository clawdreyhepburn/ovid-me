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
 * NOT supported (rejected in strict mode):
 *   - unless clauses
 *   - Nested when with boolean combinators (&& / ||)
 *   - principal == / resource == constraints in head
 *   - has operator, .contains(), decimal/IP extensions
 *   - Context conditions beyond resource.path like "..."
 */

import { evaluateWithWasm, isWasmAvailable } from './cedar-engine-wasm.js';

export type EngineMode = 'wasm' | 'fallback' | 'auto';

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

export interface ParseError {
  line: number;
  message: string;
  unsupportedFeature: string;
}

interface ParsedPolicy {
  effect: 'permit' | 'forbid';
  actions: string[] | null; // null = wildcard (matches any)
  resourceGlob: string | null; // null = wildcard
  actionNamespaces: string[]; // namespaces seen in action clause (e.g. ['Ovid', 'Jans'])
  raw: string;
}

export interface ParseOptions {
  /** Reject policies with unsupported Cedar syntax. Default: true. */
  strict?: boolean;
}

/**
 * Detect unsupported Cedar features in a policy block.
 * Returns a list of parse errors, empty if the block is fully supported.
 */
function detectUnsupportedFeatures(block: string): ParseError[] {
  const errors: ParseError[] = [];

  // Find approximate line number for the block start
  const lineNum = 1; // Simplified — block-level line tracking

  // unless clause
  if (/\bunless\s*\{/.test(block)) {
    errors.push({
      line: lineNum,
      message: 'unless clauses are not supported by the fallback engine',
      unsupportedFeature: 'unless',
    });
  }

  // principal == constraint in head
  if (/principal\s*==\s*/.test(block)) {
    errors.push({
      line: lineNum,
      message: 'principal == constraints are not supported by the fallback engine',
      unsupportedFeature: 'principal_equality',
    });
  }

  // resource == constraint in head
  if (/resource\s*==\s*/.test(block)) {
    errors.push({
      line: lineNum,
      message: 'resource == constraints are not supported by the fallback engine',
      unsupportedFeature: 'resource_equality',
    });
  }

  // has operator
  if (/\bhas\s+\w/.test(block)) {
    errors.push({
      line: lineNum,
      message: 'has operator is not supported by the fallback engine',
      unsupportedFeature: 'has',
    });
  }

  // .contains(), .containsAll(), .containsAny()
  if (/\.contains(All|Any)?\s*\(/.test(block)) {
    errors.push({
      line: lineNum,
      message: '.contains() methods are not supported by the fallback engine',
      unsupportedFeature: 'contains',
    });
  }

  // Boolean combinators in when clause (&&, ||) beyond simple resource.path like
  const whenMatch = block.match(/when\s*\{([^}]*)\}/s);
  if (whenMatch) {
    const whenBody = whenMatch[1];
    if (/&&/.test(whenBody) || /\|\|/.test(whenBody)) {
      errors.push({
        line: lineNum,
        message: 'boolean combinators (&&, ||) in when clauses are not supported by the fallback engine',
        unsupportedFeature: 'boolean_combinators',
      });
    }
    // context.X references (other than resource.path like)
    if (/context\./.test(whenBody)) {
      errors.push({
        line: lineNum,
        message: 'context conditions are not supported by the fallback engine',
        unsupportedFeature: 'context_conditions',
      });
    }
    // Unsupported when conditions (anything other than resource.path like "...")
    const stripped = whenBody.trim();
    if (stripped && !/^resource\.path\s+like\s+"[^"]*"\s*$/.test(stripped)) {
      // Check if it's a supported pattern we already flagged
      if (!errors.some(e => e.unsupportedFeature === 'boolean_combinators' || e.unsupportedFeature === 'context_conditions')) {
        errors.push({
          line: lineNum,
          message: `unsupported when condition: ${stripped.slice(0, 80)}`,
          unsupportedFeature: 'unsupported_when',
        });
      }
    }
  }

  // principal in (entity hierarchy, not action in [...])
  if (/principal\s+in\s+/.test(block)) {
    errors.push({
      line: lineNum,
      message: 'principal hierarchy (in) is not supported by the fallback engine',
      unsupportedFeature: 'principal_hierarchy',
    });
  }

  // resource in (entity hierarchy)
  if (/resource\s+in\s+/.test(block)) {
    errors.push({
      line: lineNum,
      message: 'resource hierarchy (in) is not supported by the fallback engine',
      unsupportedFeature: 'resource_hierarchy',
    });
  }

  return errors;
}

/**
 * Parse Cedar policy text into structured policies.
 *
 * @param cedarText - Cedar policy text
 * @param options - Parse options. strict (default: true) rejects unsupported syntax.
 * @throws Error if strict mode is enabled and unsupported syntax is detected
 */
export function parsePolicies(cedarText: string, options?: ParseOptions): ParsedPolicy[] {
  const strict = options?.strict ?? true;
  const policies: ParsedPolicy[] = [];
  // Split on top-level permit/forbid boundaries
  const blocks = cedarText.match(/(permit|forbid)\s*\([^;]*;/gs);
  if (!blocks) return policies;

  const allErrors: ParseError[] = [];

  for (const block of blocks) {
    // Check for unsupported features
    const errors = detectUnsupportedFeatures(block);
    if (errors.length > 0) {
      if (strict) {
        allErrors.push(...errors);
        continue; // Don't parse this block
      }
      // Non-strict: warn and skip
      for (const err of errors) {
        console.warn(`[ovid] skipping unsupported Cedar syntax: ${err.message}`);
      }
      continue;
    }

    const effect = block.trimStart().startsWith('forbid') ? 'forbid' as const : 'permit' as const;

    // Extract action constraint.
    //
    // Namespace-agnostic: we accept any `<Namespace>::Action::"<name>"` form,
    // record the namespace, and extract the action name. Policies written in
    // Ovid::, Jans::, or any other namespace are all parsed the same way.
    //
    // Parse errors (malformed action clauses that we can't interpret) produce
    // an explicit error rather than silently falling through to the wildcard
    // case. Historical bug: a `Jans::Action::...` clause used to leave
    // `actions = null`, which `policyMatchesRequest` treated as wildcard-
    // matches-every-action. That fail-open behavior is now closed — an
    // action clause that parses as NEITHER a recognized list NOR a single
    // equality is rejected as a parse error (and in strict mode, the whole
    // block is dropped).
    let actions: string[] | null = null;
    const actionNamespaces: string[] = [];

    // Sniff: does this block have an explicit `action` constraint at all?
    // A bare `action` (no `==` and no `in`) in the head means wildcard.
    // Anything else with `action` must parse fully or is an error.
    const hasActionInList = /\baction\s+in\s*\[/.test(block);
    const hasActionEq = /\baction\s*==/.test(block);

    if (hasActionInList) {
      const listMatch = block.match(/\baction\s+in\s*\[([^\]]+)\]/);
      if (listMatch) {
        const entries = [...listMatch[1].matchAll(/(?:([A-Za-z_][\w]*)::)?Action::"([^"]+)"/g)];
        if (entries.length === 0) {
          // `action in [...]` but nothing that looks like a namespaced action
          // inside. Refuse to silently treat as wildcard.
          allErrors.push({
            line: lineNumFor(cedarText, block),
            message: 'action in [...] clause contains no recognized Action::"..." entries',
            unsupportedFeature: 'malformed action list',
          });
          if (strict) continue;
          // non-strict: treat as deny-everything (empty allow list)
          actions = [];
        } else {
          actions = entries.map(m => m[2]);
          for (const m of entries) {
            const ns = m[1] ?? '';
            if (!actionNamespaces.includes(ns)) actionNamespaces.push(ns);
          }
        }
      }
    } else if (hasActionEq) {
      const singleMatch = block.match(/\baction\s*==\s*(?:([A-Za-z_][\w]*)::)?Action::"([^"]+)"/);
      if (singleMatch) {
        actions = [singleMatch[2]];
        actionNamespaces.push(singleMatch[1] ?? '');
      } else {
        // `action ==` but the right-hand side isn't a <Namespace>::Action::"X".
        // Unknown shape — refuse to interpret as wildcard.
        allErrors.push({
          line: lineNumFor(cedarText, block),
          message: 'action == clause RHS is not a recognized Action::"..."',
          unsupportedFeature: 'malformed action equality',
        });
        if (strict) continue;
        actions = [];
      }
    }
    // else: no `action` constraint at all — true wildcard.

    // Extract resource glob from when clause
    let resourceGlob: string | null = null;
    const whenMatch = block.match(/when\s*\{\s*resource\.path\s+like\s+"([^"]+)"\s*\}/);
    if (whenMatch) {
      resourceGlob = whenMatch[1];
    }

    policies.push({ effect, actions, resourceGlob, actionNamespaces, raw: block.trim() });
  }

  if (strict && allErrors.length > 0) {
    const details = allErrors.map(e => e.unsupportedFeature).join(', ');
    throw new UnsupportedCedarSyntaxError(
      `unsupported Cedar syntax: ${details}`,
      allErrors,
    );
  }

  return policies;
}

/**
 * Error thrown when strict parsing encounters unsupported Cedar features.
 */
export class UnsupportedCedarSyntaxError extends Error {
  public readonly errors: ParseError[];

  constructor(message: string, errors: ParseError[]) {
    super(message);
    this.name = 'UnsupportedCedarSyntaxError';
    this.errors = errors;
  }
}

/** Best-effort line number of `block` within `cedarText` (1-indexed). */
function lineNumFor(cedarText: string, block: string): number {
  const idx = cedarText.indexOf(block);
  if (idx < 0) return 1;
  let line = 1;
  for (let i = 0; i < idx; i++) {
    if (cedarText.charCodeAt(i) === 10) line++;
  }
  return line;
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
 * Evaluate a request using the WASM engine if available, otherwise fall back.
 * This is the preferred entry point when engine mode is 'auto' or 'wasm'.
 */
export async function evaluateMandateAsync(
  cedarText: string,
  agentJti: string,
  request: EvaluateRequest,
  engine: EngineMode = 'auto',
): Promise<{ decision: 'allow' | 'deny'; matchedPolicy?: string; reason?: string; engine: 'wasm' | 'fallback' }> {
  if (engine === 'wasm' || engine === 'auto') {
    const wasmResult = await evaluateWithWasm(cedarText, agentJti, request);
    if (wasmResult) {
      return {
        decision: wasmResult.decision,
        reason: wasmResult.reasons.join('; ') || undefined,
        engine: 'wasm',
      };
    }
    if (engine === 'wasm') {
      // WASM explicitly requested but unavailable
      return { decision: 'deny', reason: 'WASM engine unavailable', engine: 'fallback' };
    }
  }

  // Fallback to string-matching engine
  const result = evaluateMandate(cedarText, request);
  return { ...result, engine: 'fallback' };
}

/**
 * Evaluate a request against Cedar policy text (synchronous string-matching fallback).
 * Returns allow/deny with Cedar semantics (default-deny, forbid overrides permit).
 *
 * Uses strict parsing by default — rejects policies with unsupported Cedar syntax
 * rather than silently mis-evaluating them.
 */
export function evaluateMandate(
  cedarText: string,
  request: EvaluateRequest,
  options?: ParseOptions,
): { decision: 'allow' | 'deny'; matchedPolicy?: string; reason?: string } {
  let policies: ParsedPolicy[];
  try {
    policies = parsePolicies(cedarText, options);
  } catch (err) {
    if (err instanceof UnsupportedCedarSyntaxError) {
      return {
        decision: 'deny',
        reason: `unsupported Cedar syntax: ${err.errors.map(e => e.unsupportedFeature).join(', ')}. Install @janssenproject/cedarling_wasm for full Cedar support.`,
      };
    }
    throw err;
  }

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
