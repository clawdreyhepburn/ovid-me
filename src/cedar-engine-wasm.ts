/**
 * Native Cedar WASM evaluator for OVID mandate evaluation.
 *
 * Uses official `@cedar-policy/cedar-wasm` (same family as Carapace 1.0.12+).
 * Previously used @janssenproject/cedarling_wasm with a silent string-matcher
 * fallback that could not evaluate `when` clauses — that class of bug is closed
 * here: if WASM cannot decide, callers get null and must fail closed (or use
 * the explicit `engine: "fallback"` opt-in).
 */

import {
  isAuthorized,
  type AuthorizationAnswer,
  type CedarValueJson,
} from "@cedar-policy/cedar-wasm/nodejs";
import type { EvaluateRequest } from "./evaluate.js";

export interface WasmEvaluateResult {
  decision: "allow" | "deny";
  reasons: string[];
}

export interface EvaluateWithWasmOptions {
  externalSchema?: Record<string, any>;
}

let loadOk: boolean | null = null;
let loadError: string | null = null;

/**
 * Probe that native cedar-wasm is importable and callable.
 * Cached after first call.
 */
function ensureNative(): boolean {
  if (loadOk !== null) return loadOk;
  try {
    // Touch the API so a broken install fails here, not mid-eval.
    if (typeof isAuthorized !== "function") {
      throw new Error("isAuthorized is not a function");
    }
    loadOk = true;
    loadError = null;
  } catch (err: any) {
    loadOk = false;
    loadError = err?.message ?? String(err);
  }
  return loadOk;
}

/** Check if the WASM engine is available without evaluating a request. */
export async function isWasmAvailable(): Promise<boolean> {
  return ensureNative();
}

/** Get the WASM load error message, if any. */
export function getWasmLoadError(): string | null {
  return loadError;
}

/** Test-only: reset the load cache. */
export function _resetWasm(): void {
  loadOk = null;
  loadError = null;
}

/**
 * Detect the namespace used for actions in the policy. Returns the first
 * <Namespace> found in a <Namespace>::Action::"..." pattern, or 'Ovid'
 * if no namespace prefix is present (bare `Action::"X"` form).
 */
function detectNamespace(cedarText: string): string {
  const match = cedarText.match(/\b([A-Za-z_][\w]*)::Action::"/);
  return match ? match[1] : "Ovid";
}

/**
 * Rewrite bare `Type::"id"` tokens so they carry a namespace.
 * Cedar bare refs resolve to the empty namespace; Carapace-style policies
 * use bare Action/Shell/Tool and must be namespaced for schema match.
 */
function rewriteBareNamespaceTokens(cedarText: string, namespace: string): string {
  return cedarText.replace(
    /(?<![:\w])([A-Za-z_][\w]*)::"/g,
    (_match, token) => `${namespace}::${token}::"`,
  );
}

/** Extract action names from policy text (namespaced or bare). */
function extractActions(cedarText: string): string[] {
  const matches = [...cedarText.matchAll(/(?:[A-Za-z_][\w]*::)?Action::"([^"]+)"/g)];
  const actions = new Set(matches.map((m) => m[1]));
  // Base actions so empty/minimal policies still have a workable schema.
  for (const a of [
    "read_file",
    "write_file",
    "exec",
    "exec_command",
    "call_tool",
    "call_api",
    "search",
    "summarize",
  ]) {
    actions.add(a);
  }
  if (actions.size === 0) actions.add("call_tool");
  return [...actions];
}

/** Entity types referenced as resources in the policy. */
function extractResourceTypes(cedarText: string, namespace: string): string[] {
  const types = new Set<string>();
  const re = new RegExp(
    `(?:${namespace}::)?(Tool|Shell|API|Resource|File)::"`,
    "g",
  );
  for (const m of cedarText.matchAll(re)) types.add(m[1]);
  // Always include common types for request construction.
  for (const t of ["Tool", "Shell", "API", "Resource", "File"]) types.add(t);
  return [...types];
}

/**
 * Build a minimal Cedar JSON schema for the detected namespace.
 * If an external schema is provided (e.g. Carapace Jans schema), use it.
 */
function buildSchema(
  cedarText: string,
  namespace: string,
  externalSchema?: Record<string, any>,
): Record<string, any> {
  if (externalSchema && Object.keys(externalSchema).length > 0) {
    // Augment the external schema so that actions/resource types the POLICY
    // (or request) references but the schema does not declare are added. A
    // Carapace schema.json may declare only the actions Carapace itself uses
    // (e.g. exec_command); an OVID mandate can reference others (read_file,
    // call_tool). Without this, isAuthorized fails on an unknown action and we
    // would (incorrectly) fall to the string matcher. We add missing actions
    // pinned to the namespace's existing principal/resource types so they load.
    return augmentExternalSchema(externalSchema, cedarText, namespace);
  }

  const actions = extractActions(cedarText);
  const resourceTypes = extractResourceTypes(cedarText, namespace);

  const entityTypes: Record<string, any> = {
    Agent: {
      memberOfTypes: [],
      shape: {
        type: "Record",
        attributes: {
          name: { type: "String", required: false },
        },
      },
    },
  };

  for (const rt of resourceTypes) {
    entityTypes[rt] = {
      memberOfTypes: [],
      shape: {
        type: "Record",
        attributes: {
          name: { type: "String", required: false },
        },
      },
    };
  }

  // Context attributes commonly used by OVID + Carapace policies.
  const contextAttrs: Record<string, any> = {
    path: { type: "String", required: false },
    args: { type: "String", required: false },
    workdir: { type: "String", required: false },
    url: { type: "String", required: false },
    method: { type: "String", required: false },
    body: { type: "String", required: false },
    action: { type: "String", required: false },
    params_json: { type: "String", required: false },
  };

  const actionDefs: Record<string, any> = {};
  for (const a of actions) {
    actionDefs[a] = {
      appliesTo: {
        principalTypes: ["Agent"],
        resourceTypes: resourceTypes,
        context: { type: "Record", attributes: contextAttrs },
      },
    };
  }

  return {
    [namespace]: {
      entityTypes,
      actions: actionDefs,
    },
  };
}

/**
 * Add missing actions and resource types to an external (deployment) schema so
 * that a policy referencing vocabulary the schema omits still loads. Mutates a
 * shallow clone; the caller's schema object is not modified.
 */
function augmentExternalSchema(
  externalSchema: Record<string, any>,
  cedarText: string,
  namespace: string,
): Record<string, any> {
  const keys = Object.keys(externalSchema);
  const ns = keys.includes(namespace) ? namespace : keys[0];
  const nsDef = externalSchema[ns];
  if (!nsDef || typeof nsDef !== "object") return externalSchema;

  // Deep-ish clone of the one namespace we touch.
  const cloned: Record<string, any> = { ...externalSchema };
  const nsClone: Record<string, any> = {
    ...nsDef,
    entityTypes: { ...(nsDef.entityTypes ?? {}) },
    actions: { ...(nsDef.actions ?? {}) },
  };
  cloned[ns] = nsClone;

  const existingActions = new Set(Object.keys(nsClone.actions));
  const existingEntities = new Set(Object.keys(nsClone.entityTypes));

  // Principal types declared by any existing action (used to pin new actions).
  const principalTypes = new Set<string>();
  for (const a of Object.values(nsClone.actions) as any[]) {
    for (const p of a?.appliesTo?.principalTypes ?? []) principalTypes.add(p);
  }
  if (principalTypes.size === 0) {
    if (existingEntities.has("Workload")) principalTypes.add("Workload");
    else if (existingEntities.has("Agent")) principalTypes.add("Agent");
  }

  // Ensure referenced resource types exist as entity types.
  const referencedResourceTypes = extractResourceTypes(cedarText, ns);
  for (const rt of referencedResourceTypes) {
    if (!existingEntities.has(rt)) {
      nsClone.entityTypes[rt] = {
        shape: { type: "Record", attributes: {} },
      };
      existingEntities.add(rt);
    }
  }

  const resourceTypes = [...existingEntities].filter(
    (t) => t !== "Workload" && t !== "Agent",
  );

  // Context attributes commonly matched by OVID/Carapace policies.
  const contextAttrs: Record<string, any> = {
    path: { type: "EntityOrCommon", name: "String", required: false },
    args: { type: "EntityOrCommon", name: "String", required: false },
    workdir: { type: "EntityOrCommon", name: "String", required: false },
    url: { type: "EntityOrCommon", name: "String", required: false },
    method: { type: "EntityOrCommon", name: "String", required: false },
    body: { type: "EntityOrCommon", name: "String", required: false },
    action: { type: "EntityOrCommon", name: "String", required: false },
    params_json: { type: "EntityOrCommon", name: "String", required: false },
  };

  // Add any policy-referenced actions the schema doesn't declare.
  for (const a of extractActions(cedarText)) {
    if (existingActions.has(a)) continue;
    nsClone.actions[a] = {
      appliesTo: {
        principalTypes: [...principalTypes],
        resourceTypes,
        context: { type: "Record", attributes: contextAttrs },
      },
    };
  }

  return cloned;
}

/** Split a multi-statement Cedar blob into individual policies with ids. */
function splitPolicies(cedarText: string): Array<{ id: string; text: string }> {
  // Prefer statement boundaries: permit/forbid at line start after rewrite.
  const parts = cedarText
    .split(/(?=^\s*(?:@|permit|forbid)\b)/m)
    .map((s) => s.trim())
    .filter(Boolean);

  const out: Array<{ id: string; text: string }> = [];
  let i = 0;
  for (const part of parts) {
    if (!/^(?:@|permit|forbid)\b/.test(part)) continue;
    // Pull @id("...") if present
    const idMatch = part.match(/@id\("([^"]+)"\)/);
    const id = idMatch?.[1] ?? `policy-${i++}`;
    out.push({ id, text: part });
  }
  if (out.length === 0 && cedarText.trim()) {
    out.push({ id: "policy-0", text: cedarText.trim() });
  }
  return out;
}

/**
 * Build the native engine's context record. The `@cedar-policy/cedar-wasm`
 * `isAuthorized` API takes RAW JSON values for context (a JSON object whose
 * values are Cedar-JSON), NOT the `{__type,value}` tagged form used by some
 * other Cedar bindings. Passing the tagged form makes the request invalid for
 * the action and the whole evaluation fails. Objects are stringified so they
 * fit the (String) closed-record attributes in the synthesized schema.
 */
function toCedarContext(context?: Record<string, unknown>): Record<string, CedarValueJson> {
  const out: Record<string, CedarValueJson> = {};
  if (!context) return out;
  for (const [k, v] of Object.entries(context)) {
    if (v === undefined || v === null) continue;
    if (typeof v === "string") out[k] = v as unknown as CedarValueJson;
    else if (typeof v === "number" && Number.isFinite(v)) {
      out[k] = Math.trunc(v) as unknown as CedarValueJson;
    } else if (typeof v === "boolean") out[k] = v as unknown as CedarValueJson;
    else if (typeof v === "object") {
      // Closed records: stringify unknown shapes so they match String attrs.
      try {
        out[k] = JSON.stringify(v).slice(0, 16384) as unknown as CedarValueJson;
      } catch {
        /* skip */
      }
    }
  }
  return out;
}

/**
 * Infer resource entity type from request + policy vocabulary.
 */
function inferResourceType(
  request: EvaluateRequest,
  resourceTypes: string[],
): string {
  if (request.resourceType && resourceTypes.includes(request.resourceType)) {
    return request.resourceType;
  }
  // Heuristics matching OVID / Carapace call sites
  const action = request.action ?? "";
  if (action === "exec_command" || action === "exec") {
    if (resourceTypes.includes("Shell")) return "Shell";
  }
  if (action === "call_api") {
    if (resourceTypes.includes("API")) return "API";
  }
  if (action === "call_tool") {
    if (resourceTypes.includes("Tool")) return "Tool";
  }
  if (resourceTypes.includes("Resource")) return "Resource";
  if (resourceTypes.includes("File")) return "File";
  if (resourceTypes.includes("Tool")) return "Tool";
  return resourceTypes[0] ?? "Resource";
}

/**
 * Evaluate a mandate (Cedar policy set) against a request using native cedar-wasm.
 * Returns null if the engine cannot load or evaluation throws (caller fail-closes).
 */
/**
 * Ensure `actionName` is declared under schema[ns].actions. Mutates schema.
 * Pins principal/resource/context shapes from an existing action when present.
 */
function ensureActionInSchema(
  schema: Record<string, any>,
  ns: string,
  actionName: string,
  resourceTypes: string[],
): void {
  const nsDef = schema[ns];
  if (!nsDef) return;
  if (!nsDef.actions) nsDef.actions = {};
  if (nsDef.actions[actionName]) return;

  const existing = Object.values(nsDef.actions) as any[];
  const sample = existing[0];
  const principalTypes: string[] =
    sample?.appliesTo?.principalTypes ??
    (nsDef.entityTypes?.Workload
      ? ["Workload"]
      : nsDef.entityTypes?.Agent
        ? ["Agent"]
        : ["Agent"]);
  const rTypes: string[] =
    sample?.appliesTo?.resourceTypes ??
    (resourceTypes.length ? resourceTypes : ["Resource"]);
  const context =
    sample?.appliesTo?.context ?? {
      type: "Record",
      attributes: {
        path: { type: "EntityOrCommon", name: "String", required: false },
        args: { type: "EntityOrCommon", name: "String", required: false },
        params_json: { type: "EntityOrCommon", name: "String", required: false },
      },
    };

  nsDef.actions[actionName] = {
    appliesTo: { principalTypes, resourceTypes: rTypes, context },
  };
}

export async function evaluateWithWasm(
  cedarText: string,
  agentJti: string,
  request: EvaluateRequest,
  options?: EvaluateWithWasmOptions,
): Promise<WasmEvaluateResult | null> {
  if (!ensureNative()) return null;

  try {
    // Resolve the effective namespace FIRST. When an external schema is
    // supplied (e.g. Carapace's Jans schema) the policy text may use bare
    // `Action::"X"` / `Shell::"id"` references. Those must be rewritten to the
    // SCHEMA's namespace, not the policy-detected one — otherwise the request
    // (built in the schema namespace) and the policy references live in
    // different namespaces and no forbid/permit ever fires. This was the
    // Carapace-integration bug: rewriting to the detected "Ovid" namespace
    // while evaluating in "Jans" silently produced allow.
    const detected = detectNamespace(cedarText);
    let ns = detected;
    if (options?.externalSchema) {
      const keys = Object.keys(options.externalSchema);
      if (keys.length === 1) ns = keys[0];
      else if (keys.includes(detected)) ns = detected;
      else if (keys.includes("Jans")) ns = "Jans";
      else if (keys.length > 0) ns = keys[0];
    }

    const rewritten = rewriteBareNamespaceTokens(cedarText, ns);
    const schema = buildSchema(rewritten, ns, options?.externalSchema);

    const resourceTypes = extractResourceTypes(rewritten, ns);
    const policies = splitPolicies(rewritten);
    if (policies.length === 0) {
      return { decision: "deny", reasons: ["no policies defined"] };
    }

    const staticPolicies = Object.fromEntries(policies.map((p) => [p.id, p.text]));

    const resourceType = inferResourceType(request, resourceTypes);
    const resourceId = request.resource ?? "";
    const actionName = request.action ?? "call_tool";

    // Ensure the REQUEST action is declared on the schema. extractActions only
    // sees names in the policy text + a fixed base set; a deny-path probe that
    // uses an unknown action (e.g. rm_rf against a read_file permit) would
    // otherwise fail isAuthorized with "action not in schema" and return null,
    // which used to silently drop into the string matcher. Default-deny for an
    // undeclared action is correct Cedar semantics once the action exists.
    ensureActionInSchema(schema, ns, actionName, resourceTypes);

    // Resolve the principal entity type. Priority:
    //   1. request.principalType if the schema declares it (caller knows best;
    //      Carapace policies use `principal is Jans::Workload`, so an Agent-
    //      typed principal would silently miss every Workload permit and fall
    //      through to default-deny — that was the integration-real-policies bug).
    //   2. Workload if the schema declares it (Carapace/Jans convention).
    //   3. Agent if the schema declares it (Ovid convention).
    //   4. Otherwise default to Agent under the namespace.
    const schemaNs = (schema as any)[ns];
    const declaredEntities: Record<string, unknown> = schemaNs?.entityTypes ?? {};
    let principalTypeName: string;
    if (request.principalType && declaredEntities[request.principalType]) {
      principalTypeName = request.principalType;
    } else if (declaredEntities.Workload) {
      principalTypeName = "Workload";
    } else if (declaredEntities.Agent) {
      principalTypeName = "Agent";
    } else {
      principalTypeName = "Agent";
    }
    const principalUid = { type: `${ns}::${principalTypeName}`, id: agentJti || "openclaw" };

    // NOTE: we deliberately pass `entities: []`. Mirrors Carapace's working
    // call. Our synthesized/external schemas and the policies we evaluate do
    // not dereference entity attributes (they match on head + context globs),
    // so an empty entity store is correct. Supplying entities with attributes
    // NOT declared in the schema causes a hard deserialization failure.
    const call = {
      principal: principalUid,
      action: { type: `${ns}::Action`, id: actionName },
      resource: { type: `${ns}::${resourceType}`, id: resourceId },
      context: toCedarContext(request.context as Record<string, unknown> | undefined),
      schema,
      policies: { staticPolicies },
      entities: [] as unknown[],
    };

    const answer: AuthorizationAnswer = isAuthorized(call as any);
    // cedar-wasm returns { type: 'success', response: { decision, ... } } or residual/errors shapes.
    const anyAns = answer as any;
    if (anyAns?.type === "failure" || anyAns?.type === "error") {
      const msg =
        anyAns?.errors?.map?.((e: any) => e?.message ?? String(e))?.join("; ") ||
        anyAns?.message ||
        "cedar-wasm authorization failure";
      if (process.env.OVID_WASM_DEBUG === "1") {
        console.error("[ovid-me cedar-wasm] failure:", msg);
      }
      return null;
    }

    const response = anyAns?.response ?? anyAns;
    const decisionRaw = response?.decision ?? anyAns?.decision;
    const decision =
      String(decisionRaw).toLowerCase() === "allow" ? "allow" : "deny";

    const reasons: string[] = [];
    const diagnostics = response?.diagnostics ?? anyAns?.diagnostics;
    if (diagnostics?.reason) {
      for (const r of diagnostics.reason) {
        if (typeof r === "string") reasons.push(r);
        else if (r?.id) reasons.push(r.id);
        else reasons.push(JSON.stringify(r));
      }
    }
    if (diagnostics?.errors?.length) {
      for (const e of diagnostics.errors) {
        reasons.push(typeof e === "string" ? e : e?.message ?? JSON.stringify(e));
      }
    }
    if (reasons.length === 0) {
      reasons.push(decision === "allow" ? "allow" : "deny");
    }

    return { decision, reasons };
  } catch (err: any) {
    if (process.env.OVID_WASM_DEBUG === "1") {
      console.error("[ovid-me cedar-wasm] throw:", err?.message ?? err);
    }
    return null;
  }
}
