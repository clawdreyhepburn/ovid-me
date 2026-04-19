/**
 * Package version read once at module load. Single source of truth for
 * runtime identification (banner output, /well-known advertising, etc.).
 *
 * Read from package.json relative to this compiled module so there is
 * no drift between the published package version and any hardcoded
 * version string. Falls back to "unknown" only if the package.json
 * lookup fails entirely (shouldn't happen in a normal install).
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

function resolveVersion(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    // Walk up to find the first package.json above this file.
    // Typical layout: dist/version.js -> ../package.json
    //                 src/version.ts  -> ../package.json
    for (const candidate of [join(here, '..', 'package.json'), join(here, '..', '..', 'package.json')]) {
      try {
        const raw = readFileSync(candidate, 'utf-8');
        const parsed = JSON.parse(raw);
        if (parsed?.name === '@clawdreyhepburn/ovid-me' && typeof parsed.version === 'string') {
          return parsed.version;
        }
      } catch {
        // try next candidate
      }
    }
  } catch {
    // fall through
  }
  return 'unknown';
}

export const OVID_ME_VERSION: string = resolveVersion();
