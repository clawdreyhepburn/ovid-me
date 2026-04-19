/**
 * Cedarling WASM-based Cedar evaluator for OVID mandate evaluation.
 *
 * Uses @janssenproject/cedarling_wasm with Ovid:: namespace entities.
 * Falls back gracefully if WASM module is unavailable.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { EvaluateRequest } from './evaluate.js';

// Cedarling WASM types
interface CedarlingInstance {
  authorize_unsigned(request: any): Promise<any>;
  pop_logs(): any[];
}

interface CedarlingWasm {
  initSync(opts: { module: Buffer }): void;
  init(config: any): Promise<CedarlingInstance>;
}

export interface WasmEvaluateResult {
  decision: 'allow' | 'deny';
  reasons: string[];
}

let wasmModule: CedarlingWasm | null = null;
let wasmLoadAttempted = false;
let wasmLoadError: string | null = null;

/**
 * Try to load the Cedarling WASM module. Safe to call multiple times —
 * only attempts loading once.
 */
async function ensureWasm(): Promise<CedarlingWasm | null> {
  if (wasmLoadAttempted) return wasmModule;
  wasmLoadAttempted = true;

  try {
    // Dynamic import — optional dependency may not be installed
    const modName = '@janssenproject/cedarling_wasm';
    const mod = await import(/* @vite-ignore */ modName) as CedarlingWasm;
    const modPath = fileURLToPath(import.meta.resolve(/* @vite-ignore */ modName));
    const wasmPath = join(dirname(modPath), 'cedarling_wasm_bg.wasm');
    const wasmBytes = readFileSync(wasmPath);
    (mod as any).initSync({ module: wasmBytes });
    wasmModule = mod;
  } catch (err: any) {
    wasmLoadError = err.message;
    wasmModule = null;
  }

  return wasmModule;
}

/**
 * Check if the WASM engine is available without creating an instance.
 */
export async function isWasmAvailable(): Promise<boolean> {
  return (await ensureWasm()) !== null;
}

/**
 * Get the WASM load error message, if any.
 */
export function getWasmLoadError(): string | null {
  return wasmLoadError;
}

/**
 * Detect the namespace used for actions in the policy. Returns the first
 * <Namespace> found in a <Namespace>::Action::"..." pattern, or 'Ovid'
 * if no namespace prefix is present (bare `Action::"X"` form used by
 * Carapace deployments). Policies using a mix of namespaces will use
 * whichever appears first (this is uncommon; Cedar schemas are per-
 * namespace).
 */
function detectNamespace(cedarText: string): string {
  const match = cedarText.match(/\b([A-Za-z_][\w]*)::Action::"/);
  return match ? match[1] : 'Ovid';
}

/**
 * Extract all action names referenced in Cedar policy text, regardless
 * of namespace. Accepts both `Foo::Action::"X"` and bare `Action::"X"`.
 * Always includes a handful of base actions so that an empty-policy
 * (or policy missing actions) still has a workable schema.
 */
function extractActions(cedarText: string): string[] {
  const matches = [...cedarText.matchAll(/(?:[A-Za-z_][\w]*::)?Action::"([^"]+)"/g)];
  const actions = new Set(matches.map(m => m[1]));
  // Always include base actions so the runtime request.action is in schema.
  actions.add('read_file');
  actions.add('write_file');
  actions.add('exec');
  return [...actions];
}

/**
 * Build a Cedarling policy store from Cedar policy text for the Ovid namespace.
 * Dynamically generates schema actions from the policy text.
 */
/**
 * Build a Cedarling policy store + schema for the detected namespace.
 *
 * The schema root key, principal entity type, and resource entity type
 * all use whatever namespace the policy declares (e.g. 'Ovid', 'Jans').
 * Historical bug: the schema was hardcoded to 'Ovid' which caused
 * Jans::-namespaced policies to either error or be silently ignored
 * by Cedarling.
 */
function buildPolicyStore(
  cedarText: string,
  namespace: string,
  requestAction?: string,
): any {
  const actionNames = extractActions(cedarText);
  // Also include the request action (it must be in the schema even if not in policy).
  if (requestAction && !actionNames.includes(requestAction)) {
    actionNames.push(requestAction);
  }

  const actions: Record<string, any> = {};
  for (const name of actionNames) {
    actions[name] = {
      appliesTo: {
        principalTypes: ['Agent'],
        resourceTypes: ['Resource'],
        context: { type: 'Record', attributes: {} },
      },
    };
  }

  const schema: Record<string, any> = {};
  schema[namespace] = {
    entityTypes: {
      Agent: {
        shape: {
          type: 'Record',
          attributes: {
            name: { type: 'EntityOrCommon', name: 'String', required: false },
          },
        },
      },
      Resource: {
        shape: {
          type: 'Record',
          attributes: {
            path: { type: 'EntityOrCommon', name: 'String', required: false },
          },
        },
      },
    },
    actions,
  };

  // Cedarling's policy_content decoder expects ONE Cedar statement per
  // policy entry. Multi-statement policy text (e.g. a permit + a forbid
  // concatenated together, which is common in Carapace deployments)
  // will fail to decode if we submit it as a single blob. Split on
  // top-level `permit(` / `forbid(` boundaries and submit each as its
  // own entry under a deterministic id.
  const statements = cedarText.match(/(?:permit|forbid)\s*\([^;]*;/gs) ?? [];
  const policies: Record<string, any> = {};
  if (statements.length === 0) {
    // Empty or malformed policy text. Submit an empty policy so the
    // evaluator runs cleanly (and denies by default).
    policies.mandate = {
      description: 'OVID mandate policy (empty)',
      creation_date: new Date().toISOString(),
      policy_content: Buffer.from('').toString('base64'),
    };
  } else {
    statements.forEach((stmt, idx) => {
      policies[`mandate_${idx}`] = {
        description: `OVID mandate policy #${idx}`,
        creation_date: new Date().toISOString(),
        policy_content: Buffer.from(stmt.trim()).toString('base64'),
      };
    });
  }

  return {
    cedar_version: 'v4.0.0',
    policy_stores: {
      ovid: {
        name: 'OVID',
        description: 'OVID mandate evaluation',
        policies,
        schema: Buffer.from(JSON.stringify(schema)).toString('base64'),
        trusted_issuers: {},
      },
    },
  };
}

/**
 * Evaluate a mandate request using Cedarling WASM.
 *
 * @returns null if WASM is unavailable (caller should fall back)
 */
export async function evaluateWithWasm(
  cedarText: string,
  agentJti: string,
  request: EvaluateRequest,
): Promise<WasmEvaluateResult | null> {
  const wasm = await ensureWasm();
  if (!wasm) return null;

  try {
    const namespace = detectNamespace(cedarText);
    const agentType = `${namespace}::Agent`;
    const resourceType = `${namespace}::Resource`;
    const policyStore = buildPolicyStore(cedarText, namespace, request.action);
    const config = {
      CEDARLING_APPLICATION_NAME: 'OVID',
      CEDARLING_POLICY_STORE_LOCAL: JSON.stringify(policyStore),
      CEDARLING_LOG_TYPE: 'off',
      CEDARLING_USER_AUTHZ: 'disabled',
      CEDARLING_WORKLOAD_AUTHZ: 'enabled',
      CEDARLING_JWT_SIG_VALIDATION: 'disabled',
      CEDARLING_JWT_SIGNATURE_ALGORITHMS_SUPPORTED: ['ES256'],
      CEDARLING_ID_TOKEN_TRUST_MODE: 'strict',
      CEDARLING_MAPPING_WORKLOAD: agentType,
      CEDARLING_PRINCIPAL_BOOLEAN_OPERATION: {
        or: [{ '===': [{ var: agentType }, 'ALLOW'] }],
      },
    };

    const instance = await wasm.init(config);

    const result = await instance.authorize_unsigned({
      principals: [
        {
          cedar_entity_mapping: {
            entity_type: agentType,
            id: agentJti,
          },
          name: agentJti,
        },
      ],
      action: `${namespace}::Action::"${request.action}"`,
      resource: {
        cedar_entity_mapping: {
          entity_type: resourceType,
          id: request.resource,
        },
        path: request.resource,
      },
      context: request.context ?? {},
    });

    const decision = result.decision ? 'allow' : 'deny';
    const reasons: string[] = [];

    try {
      const resultJson = JSON.parse(result.json_string());
      if (resultJson.principals) {
        for (const [, princResult] of Object.entries(resultJson.principals) as any) {
          const diag = princResult.diagnostics;
          if (diag?.reason) {
            for (const r of diag.reason) {
              reasons.push(`${princResult.decision ? 'permit' : 'deny'}: ${r}`);
            }
          }
        }
      }
    } catch {
      // json_string() might not be available on all versions
    }

    return { decision: decision as 'allow' | 'deny', reasons };
  } catch (err: any) {
    // Surface WASM errors when OVID_WASM_DEBUG=1 — otherwise the whole WASM
    // path can silently return null and fall back to the string matcher,
    // which can mask real integration regressions (e.g. Cedarling schema
    // format changes).
    if (process.env.OVID_WASM_DEBUG) {
      // eslint-disable-next-line no-console
      console.error('[ovid:wasm] evaluation failed:', err?.message ?? err);
    }
    return null;
  }
}

/**
 * Reset WASM state (for testing).
 */
export function _resetWasm(): void {
  wasmModule = null;
  wasmLoadAttempted = false;
  wasmLoadError = null;
}
