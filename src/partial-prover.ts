/**
 * Cedar partial-evaluation prover — shells out to the Rust agent-authz-prover
 * `partial` subcommand to compute, for a mandate and a request with UNKNOWN
 * components, whether the mandate Allows / Denies / Depends-on the unknowns.
 *
 * This is the "authorization as a planning input" primitive (the Windley
 * Loop): an agent asks "for action A on resource-shape rho, what can I do?"
 * and receives a MAP of its action space rather than a single post-hoc
 * verdict. On `Depends`, the prover returns the nontrivial *residual* policies
 * — the exact conditions under which Allow holds — so the planner knows what
 * it would need to satisfy.
 *
 * Uses cedar-policy's `is_authorized_partial` (experimental `partial-eval`
 * feature) in the Rust binary. Falls back gracefully if the binary is missing
 * or times out.
 */

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { writeFileSync, unlinkSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

/** Verdict of a partial-evaluation query over unknown request components. */
export type PartialVerdict = 'Allow' | 'Deny' | 'Depends';

export interface PartialProbeResult {
  /**
   * `Allow`   — mandate permits for ALL substitutions of the unknowns.
   * `Deny`    — mandate denies for ALL substitutions.
   * `Depends` — decision depends on the unknowns; see `residuals`.
   * `null`    — prover unavailable / inconclusive (see `reason`).
   */
  verdict: PartialVerdict | null;
  /**
   * On `Depends`, the nontrivial residual policies: the conditions under which
   * the request would be Allowed. Empty on Allow/Deny.
   */
  residuals: string[];
  /** Unknown entities the planner would need to resolve (on `Depends`). */
  unknowns: string[];
  reason?: string;
  durationMs?: number;
}

/** A single (action, resource-shape) query in an action-space probe. */
export interface OptionQuery {
  /** Action EntityUID, e.g. `Ovid::Action::"read"`. */
  action: string;
  /**
   * Resource component. Prefix with `?` for an UNKNOWN-but-typed resource
   * (e.g. `?Ovid::File`), or pass a concrete EntityUID
   * (e.g. `Ovid::File::"wsfile"`).
   */
  resource: string;
  /** Optional principal EntityUID or `?Type`; defaults to fully unknown. */
  principal?: string;
}

export interface OptionResult extends PartialProbeResult {
  action: string;
  resource: string;
}

const DEFAULT_PROVER_PATH = join(
  process.env.HOME ?? '/root',
  '.agent-authz/prover/target/release/agent-authz-prover',
);

/** Check if the prover binary exists at the expected path. */
export function partialProverExists(binaryPath?: string): boolean {
  return existsSync(binaryPath ?? DEFAULT_PROVER_PATH);
}

/**
 * Run a single partial-evaluation query.
 *
 * @param mandate   Cedar policy text of the task mandate.
 * @param query     The (action, resource, principal?) shape to probe.
 * @param opts.entitiesJson  Optional Cedar entities JSON (needed when a
 *                           component is concrete and its attributes matter).
 * @param opts.timeoutMs     Kill after this many ms (default 5000).
 * @param opts.binaryPath    Path to the prover binary.
 */
export async function probePartial(
  mandate: string,
  query: OptionQuery,
  opts?: { entitiesJson?: string; timeoutMs?: number; binaryPath?: string },
): Promise<PartialProbeResult> {
  const start = Date.now();
  const timeoutMs = opts?.timeoutMs ?? 5000;
  const binaryPath = opts?.binaryPath ?? DEFAULT_PROVER_PATH;

  if (!existsSync(binaryPath)) {
    return { verdict: null, residuals: [], unknowns: [], reason: 'prover binary not found', durationMs: Date.now() - start };
  }

  const id = randomUUID().slice(0, 8);
  const mandateFile = join(tmpdir(), `ovid-mandate-${id}.cedar`);
  let entitiesFile: string | undefined;

  try {
    writeFileSync(mandateFile, mandate, 'utf-8');
    const args = [
      'partial',
      '--mandate', mandateFile,
      '--action', query.action,
      '--resource', query.resource,
    ];
    if (query.principal) {
      args.push('--principal', query.principal);
    }
    if (opts?.entitiesJson) {
      entitiesFile = join(tmpdir(), `ovid-entities-${id}.json`);
      writeFileSync(entitiesFile, opts.entitiesJson, 'utf-8');
      args.push('--entities', entitiesFile);
    }

    const result = await runPartial(binaryPath, args, timeoutMs);
    return { ...result, durationMs: Date.now() - start };
  } finally {
    try { unlinkSync(mandateFile); } catch {}
    if (entitiesFile) { try { unlinkSync(entitiesFile); } catch {} }
  }
}

/**
 * Probe a whole action space: run `probePartial` for each query and return a
 * map of Allow / Deny / Depends per (action, resource). This is the ergonomic
 * "what can I do for this task?" call an agent makes before planning.
 */
export async function probeOptions(
  mandate: string,
  queries: OptionQuery[],
  opts?: { entitiesJson?: string; timeoutMs?: number; binaryPath?: string },
): Promise<OptionResult[]> {
  const out: OptionResult[] = [];
  for (const q of queries) {
    const r = await probePartial(mandate, q, opts);
    out.push({ ...r, action: q.action, resource: q.resource });
  }
  return out;
}

function runPartial(
  binaryPath: string,
  args: string[],
  timeoutMs: number,
): Promise<PartialProbeResult> {
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let killed = false;

    const proc = spawn(binaryPath, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: timeoutMs,
    });

    const timer = timeoutMs > 0 ? setTimeout(() => {
      killed = true;
      proc.kill('SIGKILL');
    }, timeoutMs) : null;

    proc.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
    proc.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });

    proc.on('error', (err: Error) => {
      if (timer) clearTimeout(timer);
      resolve({ verdict: null, residuals: [], unknowns: [], reason: `prover error: ${err.message}` });
    });

    proc.on('close', (code: number | null) => {
      if (timer) clearTimeout(timer);

      if (killed) {
        resolve({ verdict: null, residuals: [], unknowns: [], reason: `prover timed out after ${timeoutMs}ms` });
        return;
      }

      const output = (stdout + stderr).trim();
      resolve(parsePartialOutput(output, code));
    });
  });
}

/**
 * Parse the prover's `partial:` output. Recognizes:
 *   partial: Allow | Deny | Depends
 *   residual: <cedar policy text>   (zero or more, only on Depends)
 *   unknowns: <comma-separated euids>
 */
export function parsePartialOutput(output: string, code: number | null): PartialProbeResult {
  const lines = output.split('\n');
  const verdictLine = lines.find((l) => l.trim().startsWith('partial:'));

  if (!verdictLine) {
    return {
      verdict: null,
      residuals: [],
      unknowns: [],
      reason:
        output.toLowerCase().includes('usage') || output.toLowerCase().includes('unrecognised')
          ? `prover does not support partial mode (exit ${code})`
          : output || `prover inconclusive (exit ${code})`,
    };
  }

  const v = verdictLine.split(':')[1]?.trim();
  let verdict: PartialVerdict | null = null;
  if (v === 'Allow' || v === 'Deny' || v === 'Depends') verdict = v;

  const residuals: string[] = [];
  for (const l of lines) {
    const t = l.trim();
    if (t.startsWith('residual:')) {
      const body = t.slice('residual:'.length).trim();
      if (body && body !== '(none non-trivial)') residuals.push(body);
    }
  }

  let unknowns: string[] = [];
  const unkLine = lines.find((l) => l.trim().startsWith('unknowns:'));
  if (unkLine) {
    unknowns = unkLine
      .slice(unkLine.indexOf(':') + 1)
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
  }

  return { verdict, residuals, unknowns };
}
