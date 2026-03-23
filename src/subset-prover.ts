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

export interface SubsetProofResult {
  proven: boolean;
  reason?: string;
  durationMs?: number;
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
