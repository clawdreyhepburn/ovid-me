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
 * Extract all action names referenced in Cedar policy text.
 * Scans for Ovid::Action::"..." patterns and includes base actions.
 */
function extractActions(cedarText: string): string[] {
  const matches = [...cedarText.matchAll(/Ovid::Action::"([^"]+)"/g)];
  const actions = new Set(matches.map(m => m[1]));
  // Always include base actions
  actions.add('read_file');
  actions.add('write_file');
  actions.add('exec');
  return [...actions];
}

/**
 * Build a Cedarling policy store from Cedar policy text for the Ovid namespace.
 * Dynamically generates schema actions from the policy text.
 */
function buildPolicyStore(cedarText: string, requestAction?: string): any {
  const actionNames = extractActions(cedarText);
  // Also include the request action (it must be in the schema even if not in policy)
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

  const schema = {
    Ovid: {
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
    },
  };

  const policies: Record<string, any> = {
    mandate: {
      description: 'OVID mandate policy',
      creation_date: new Date().toISOString(),
      policy_content: Buffer.from(cedarText).toString('base64'),
    },
  };

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
    const policyStore = buildPolicyStore(cedarText, request.action);
    const config = {
      CEDARLING_APPLICATION_NAME: 'OVID',
      CEDARLING_POLICY_STORE_LOCAL: JSON.stringify(policyStore),
      CEDARLING_LOG_TYPE: 'off',
      CEDARLING_USER_AUTHZ: 'disabled',
      CEDARLING_WORKLOAD_AUTHZ: 'enabled',
      CEDARLING_JWT_SIG_VALIDATION: 'disabled',
      CEDARLING_JWT_SIGNATURE_ALGORITHMS_SUPPORTED: ['ES256'],
      CEDARLING_ID_TOKEN_TRUST_MODE: 'strict',
      CEDARLING_MAPPING_WORKLOAD: 'Ovid::Agent',
      CEDARLING_PRINCIPAL_BOOLEAN_OPERATION: {
        or: [{ '===': [{ var: 'Ovid::Agent' }, 'ALLOW'] }],
      },
    };

    const instance = await wasm.init(config);

    const result = await instance.authorize_unsigned({
      principals: [
        {
          cedar_entity_mapping: {
            entity_type: 'Ovid::Agent',
            id: agentJti,
          },
          name: agentJti,
        },
      ],
      action: `Ovid::Action::"${request.action}"`,
      resource: {
        cedar_entity_mapping: {
          entity_type: 'Ovid::Resource',
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
    // WASM evaluation failed — return null so caller falls back
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
