/**
 * SMT subset prover — shells out to the Rust agent-authz-prover binary
 * to formally verify that a child mandate is a subset of a parent policy.
 *
 * Falls back gracefully if the binary is not found or times out.
 */

import { spawn } from 'node:child_process';
import { writeFileSync, unlinkSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';

/**
 * A concrete counterexample request produced by cvc5 when a mandate is NOT a
 * subset of its parent: a request the child policy allows and the parent does
 * not. Entity references are the Cedar EntityUIDs the solver's model assigned,
 * e.g. `Ovid::Action::"exec"`, `Ovid::Shell::""`.
 */
export interface Counterexample {
  principal: string;
  action: string;
  resource: string;
}

export interface SubsetProofResult {
  proven: boolean;
  reason?: string;
  durationMs?: number;
  /**
   * When `proven` is false and the prover produced a concrete witness, the
   * counterexample request (child allows, parent denies). Absent when the
   * violation was detected but no model could be concretized (out-of-fragment
   * cases), or when `proven` is true.
   */
  counterexample?: Counterexample;
}

const DEFAULT_PROVER_PATH = join(
  process.env.HOME ?? '/root',
  '.agent-authz/prover/target/release/agent-authz-prover',
);

/**
 * Check if the prover binary exists at the expected path.
 */
export function proverBinaryExists(binaryPath?: string): boolean {
  return existsSync(binaryPath ?? DEFAULT_PROVER_PATH);
}

/**
 * Verify that childPolicy ⊆ parentPolicy using the SMT prover.
 *
 * Writes both policies to temp files, invokes the prover binary,
 * and parses the output.
 *
 * @param parentPolicy - Cedar policy text of the parent
 * @param childPolicy - Cedar policy text of the child mandate
 * @param opts.timeoutMs - Kill process after this many ms (default 5000)
 * @param opts.binaryPath - Path to the prover binary
 */
export async function proveSubset(
  parentPolicy: string,
  childPolicy: string,
  opts?: { timeoutMs?: number; binaryPath?: string },
): Promise<SubsetProofResult> {
  const start = Date.now();
  const timeoutMs = opts?.timeoutMs ?? 5000;
  const binaryPath = opts?.binaryPath ?? DEFAULT_PROVER_PATH;

  if (!existsSync(binaryPath)) {
    return { proven: false, reason: 'prover binary not found', durationMs: Date.now() - start };
  }

  const id = randomUUID().slice(0, 8);
  const parentFile = join(tmpdir(), `ovid-parent-${id}.cedar`);
  const childFile = join(tmpdir(), `ovid-child-${id}.cedar`);

  try {
    writeFileSync(parentFile, parentPolicy, 'utf-8');
    writeFileSync(childFile, childPolicy, 'utf-8');

    const result = await runProver(binaryPath, parentFile, childFile, timeoutMs);
    return { ...result, durationMs: Date.now() - start };
  } finally {
    // Clean up temp files
    try { unlinkSync(parentFile); } catch {}
    try { unlinkSync(childFile); } catch {}
  }
}

function runProver(
  binaryPath: string,
  parentFile: string,
  childFile: string,
  timeoutMs: number,
): Promise<SubsetProofResult> {
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let killed = false;

    const proc = spawn(binaryPath, ['subset', '--parent', parentFile, '--child', childFile], {
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: timeoutMs,
    });

    const timer = timeoutMs > 0 ? setTimeout(() => {
      killed = true;
      proc.kill('SIGKILL');
    }, timeoutMs) : null;

    proc.stdout.on('data', (data: Buffer) => { stdout += data.toString(); });
    proc.stderr.on('data', (data: Buffer) => { stderr += data.toString(); });

    proc.on('error', (err: Error) => {
      if (timer) clearTimeout(timer);
      resolve({ proven: false, reason: `prover error: ${err.message}` });
    });

    // (parseCounterexample defined at module scope below)
    proc.on('close', (code: number | null) => {
      if (timer) clearTimeout(timer);

      if (killed) {
        resolve({ proven: false, reason: `prover timed out after ${timeoutMs}ms` });
        return;
      }

      // Parse output — look for explicit subset proof confirmation
      const output = (stdout + stderr).trim();
      const lower = output.toLowerCase();

      // Only accept explicit subset proof markers, not generic verification output
      if (lower.includes('subset: proven') || lower.includes('subset_proven') ||
          (lower.includes('subset') && lower.includes('true') && !lower.includes('error'))) {
        resolve({ proven: true });
      } else if (lower.includes('subset: not-proven') || lower.includes('subset_not_proven')) {
        // Genuine non-subset. Extract the concrete counterexample witness the
        // prover emitted (a `counterexample: {json}` line), if present.
        resolve({ proven: false, reason: output, counterexample: parseCounterexample(output) });
      } else if (code !== 0 || lower.includes('error') || lower.includes('usage') || lower.includes('unknown')) {
        // Binary doesn't support subset mode or errored
        resolve({
          proven: false,
          reason: `prover does not support subset mode (exit ${code})`,
        });
      } else {
        resolve({
          proven: false,
          reason: output || `prover inconclusive (exit ${code})`,
        });
      }
    });
  });
}

/**
 * Parse the `counterexample: {json}` line the Rust prover emits alongside a
 * `subset: not-proven` verdict. Returns undefined when no witness line is
 * present (e.g. the violation was detected but no concrete model could be
 * extracted).
 */
export function parseCounterexample(output: string): Counterexample | undefined {
  const line = output.split('\n').find((l) => l.trim().startsWith('counterexample:'));
  if (!line) return undefined;
  const jsonStart = line.indexOf('{');
  if (jsonStart < 0) return undefined;
  try {
    const parsed = JSON.parse(line.slice(jsonStart)) as Partial<Counterexample>;
    if (
      typeof parsed.principal === 'string' &&
      typeof parsed.action === 'string' &&
      typeof parsed.resource === 'string'
    ) {
      return { principal: parsed.principal, action: parsed.action, resource: parsed.resource };
    }
  } catch {
    /* malformed line — treat as no witness */
  }
  return undefined;
}

/**
 * Concrete re-validation of a counterexample (SynSec §4.4): feed the witness
 * request back through the Cedar engine against both the child and parent
 * policies and confirm it reproduces a genuine decision divergence (child
 * allows, parent does not). This guards against SMT-encoding bugs: a witness
 * the solver claims is a divergence but that Cedar does NOT actually decide
 * divergently indicates an encoding fault, and the counterexample is rejected
 * rather than reported.
 *
 * `evaluator` is injected (the caller passes OVID-ME's Cedar evaluator) so this
 * module stays free of a hard dependency on the WASM engine. Returns:
 *   - { validated: true }  — Cedar confirms child=allow, parent!=allow
 *   - { validated: false, reason } — Cedar disagreed (possible encoding bug),
 *                                    or the engine was unavailable/inconclusive
 */
export interface CounterexampleValidation {
  validated: boolean;
  reason?: string;
  childDecision?: 'allow' | 'deny';
  parentDecision?: 'allow' | 'deny';
}

export async function revalidateCounterexample(
  cex: Counterexample,
  parentPolicy: string,
  childPolicy: string,
  evaluator: (
    policyText: string,
    req: { action: string; resource: string; resourceType?: string; principalType?: string },
  ) => Promise<{ decision: 'allow' | 'deny' } | null>,
): Promise<CounterexampleValidation> {
  // Parse `Namespace::Type::"id"` EntityUIDs into the fields the evaluator
  // expects (bare action name, resource id + type, principal type).
  const parseUid = (uid: string): { type?: string; id: string } => {
    // e.g. Ovid::Action::"exec"  ->  type "Action", id "exec"
    //      Ovid::Shell::""       ->  type "Shell",  id ""
    const m = uid.match(/(?:[A-Za-z_]\w*::)*([A-Za-z_]\w*)::"([^"]*)"$/);
    if (m) return { type: m[1], id: m[2] };
    return { id: uid };
  };

  const action = parseUid(cex.action).id;
  const res = parseUid(cex.resource);
  const prin = parseUid(cex.principal);
  const req = {
    action,
    resource: res.id,
    resourceType: res.type,
    principalType: prin.type,
  };

  const childRes = await evaluator(childPolicy, req);
  const parentRes = await evaluator(parentPolicy, req);

  if (!childRes || !parentRes) {
    return {
      validated: false,
      reason: 'Cedar engine unavailable for counterexample re-validation',
    };
  }

  const childDecision = childRes.decision;
  const parentDecision = parentRes.decision;

  // The witness must reproduce the divergence the solver claimed:
  // child allows it, parent does not.
  if (childDecision === 'allow' && parentDecision !== 'allow') {
    return { validated: true, childDecision, parentDecision };
  }

  return {
    validated: false,
    reason:
      `Cedar re-evaluation did not reproduce the claimed divergence ` +
      `(child=${childDecision}, parent=${parentDecision}); possible SMT-encoding fault`,
    childDecision,
    parentDecision,
  };
}
