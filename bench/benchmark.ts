/**
 * OVID-ME Benchmark Harness
 * Run: npx tsx bench/benchmark.ts
 */

import { performance } from 'node:perf_hooks';
import { evaluateMandate, type EvaluateRequest } from '../src/evaluate.js';
import { proveSubset, proverBinaryExists } from '../src/subset-prover.js';
import { AuditDatabase } from '../src/audit-db.js';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeFileSync, unlinkSync } from 'node:fs';

const ITERATIONS = 1000;
const WARMUP = 50;

interface Stats { p50: number; p95: number; p99: number; min: number; max: number; mean: number; }

function computeStats(samples: number[]): Stats {
  const sorted = [...samples].sort((a, b) => a - b);
  const n = sorted.length;
  return {
    p50: sorted[Math.floor(n * 0.5)],
    p95: sorted[Math.floor(n * 0.95)],
    p99: sorted[Math.floor(n * 0.99)],
    min: sorted[0], max: sorted[n - 1],
    mean: samples.reduce((a, b) => a + b, 0) / n,
  };
}

function printStats(name: string, stats: Stats) {
  console.log(`  ${name}:`);
  console.log(`    p50=${stats.p50.toFixed(3)}ms  p95=${stats.p95.toFixed(3)}ms  p99=${stats.p99.toFixed(3)}ms`);
  console.log(`    min=${stats.min.toFixed(3)}ms  max=${stats.max.toFixed(3)}ms  mean=${stats.mean.toFixed(3)}ms\n`);
}

async function bench(name: string, fn: () => void | Promise<void>): Promise<Stats> {
  for (let i = 0; i < WARMUP; i++) await fn();
  const samples: number[] = [];
  for (let i = 0; i < ITERATIONS; i++) {
    const start = performance.now();
    await fn();
    samples.push(performance.now() - start);
  }
  const stats = computeStats(samples);
  printStats(name, stats);
  return stats;
}

async function main() {
  console.log(`OVID-ME Benchmark — ${ITERATIONS} iterations, ${WARMUP} warmup\n`);
  console.log(`Platform: ${process.platform} ${process.arch}`);
  console.log(`Node: ${process.version}\n`);

  const results: Record<string, Stats> = {};

  const simplePolicySet = 'permit(principal, action == Ovid::Action::"tool_call", resource) when { resource.name == "web_search" };';
  const complexPolicySet = [
    'permit(principal, action == Ovid::Action::"tool_call", resource) when { resource.name == "web_search" };',
    'permit(principal, action == Ovid::Action::"tool_call", resource) when { resource.name == "read_file" };',
    'permit(principal, action == Ovid::Action::"tool_call", resource) when { resource.name == "web_fetch" };',
    'forbid(principal, action == Ovid::Action::"tool_call", resource) when { resource.name == "exec" };',
    'forbid(principal, action == Ovid::Action::"tool_call", resource) when { resource.name == "rm" };',
  ].join('\n');

  const parentPolicySet = [
    'permit(principal, action == Ovid::Action::"tool_call", resource) when { resource.name == "web_search" };',
    'permit(principal, action == Ovid::Action::"tool_call", resource) when { resource.name == "read_file" };',
    'permit(principal, action == Ovid::Action::"tool_call", resource) when { resource.name == "web_fetch" };',
    'permit(principal, action == Ovid::Action::"tool_call", resource) when { resource.name == "write_file" };',
    'forbid(principal, action == Ovid::Action::"tool_call", resource) when { resource.name == "exec" };',
    'forbid(principal, action == Ovid::Action::"tool_call", resource) when { resource.name == "rm" };',
  ].join('\n');

  // 1. Cedar evaluation — simple policy (fallback evaluator)
  const simpleReq: EvaluateRequest = {
    principal: 'Ovid::Agent::"sub-agent"',
    action: 'Ovid::Action::"tool_call"',
    resource: { type: 'Ovid::Tool', id: 'web_search', attrs: { name: 'web_search' } },
  };

  results['eval_simple'] = await bench('Cedar eval — simple (1 policy)', () => {
    evaluateMandate(simplePolicySet, simpleReq);
  });

  // 2. Cedar evaluation — complex policy
  results['eval_complex'] = await bench('Cedar eval — complex (5 policies)', () => {
    evaluateMandate(complexPolicySet, simpleReq);
  });

  // 3. Cedar evaluation — deny case
  const denyReq: EvaluateRequest = {
    principal: 'Ovid::Agent::"sub-agent"',
    action: 'Ovid::Action::"tool_call"',
    resource: { type: 'Ovid::Tool', id: 'exec', attrs: { name: 'exec' } },
  };

  results['eval_deny'] = await bench('Cedar eval — deny case', () => {
    evaluateMandate(complexPolicySet, denyReq);
  });

  // 4. Subset prover
  const hasBinary = proverBinaryExists();
  console.log(`  Prover binary available: ${hasBinary}\n`);

  if (hasBinary) {
    results['subset_simple'] = await bench('Subset proof — 1 vs 6 policies', async () => {
      await proveSubset(simplePolicySet, parentPolicySet);
    });

    results['subset_complex'] = await bench('Subset proof — 5 vs 6 policies', async () => {
      await proveSubset(complexPolicySet, parentPolicySet);
    });
  }

  // 5. Audit DB write
  const dbPath = join(tmpdir(), `ovid-bench-${Date.now()}.db`);
  const db = new AuditDatabase(dbPath);

  // Seed some issuances so recordDecision has valid agent JTIs
  for (let i = 0; i < 100; i++) {
    db.recordIssuance({
      jti: `agent-${i}`,
      subject: `sub-agent-${i}`,
      issuer: 'parent',
      mandate_summary: 'bench',
      parent_chain: i > 0 ? [`agent-${i-1}`] : [],
      exp: Date.now() + 3600000,
    });
  }

  let counter = 0;
  results['audit_write'] = await bench('Audit DB write', () => {
    db.recordDecision(
      `agent-${counter % 100}`,
      'tool_call',
      'web_search',
      'allow-proven',
      ['policy-1'],
    );
    counter++;
  });

  // 6. Audit DB read (after 1000+ writes)
  results['audit_read'] = await bench('Audit DB query (overview)', () => {
    db.getOverview();
  });

  try { unlinkSync(dbPath); } catch {}

  // Summary
  console.log('=== Summary (ms) ===');
  console.log('Operation                    | p50    | p95    | p99    | mean');
  console.log('-----------------------------|--------|--------|--------|-------');
  for (const [name, s] of Object.entries(results)) {
    console.log(
      `${name.padEnd(29)}| ${s.p50.toFixed(3).padStart(6)} | ${s.p95.toFixed(3).padStart(6)} | ${s.p99.toFixed(3).padStart(6)} | ${s.mean.toFixed(3).padStart(6)}`
    );
  }

  const jsonPath = new URL('./results.json', import.meta.url).pathname;
  writeFileSync(jsonPath, JSON.stringify({
    timestamp: new Date().toISOString(),
    platform: `${process.platform} ${process.arch}`,
    node: process.version,
    iterations: ITERATIONS,
    warmup: WARMUP,
    results,
  }, null, 2));
  console.log(`\nResults written to ${jsonPath}`);
}

main().catch(console.error);
