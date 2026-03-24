/**
 * OVID Configuration
 *
 * All fields are optional — sensible defaults are applied.
 * See docs/CONFIG.md for detailed documentation and deployment profiles.
 */

// Re-export types from ovid for convenience
export type { AuthorizationDetail, CedarMandate } from '@clawdreyhepburn/ovid'
import type { AuthorizationDetail } from '@clawdreyhepburn/ovid'
/** @deprecated Use AuthorizationDetail */
type CedarMandate = AuthorizationDetail;

/**
 * Interface for retrieving a principal's effective policy from the
 * deployment-level policy engine (e.g., Carapace, OPA, static file).
 *
 * OVID depends on this interface, not on any specific implementation.
 */
export interface PolicySource {
  /**
   * Return the effective Cedar policy set for the given principal.
   *
   * @param principal - Agent ID (matches `iss` claim of the OVID being minted)
   * @returns Cedar policy text, or null if no effective policy exists
   */
  getEffectivePolicy(principal: string): Promise<string | null>
}

export interface OvidConfig {
  // ── Engine Selection ──────────────────────────────────────────

  /**
   * Which Cedar evaluation engine to use.
   *
   * - "wasm"     — Cedarling WASM only (fails if unavailable)
   * - "fallback" — String-matching engine only
   * - "auto"     — Try WASM first, fall back to string matcher
   */
  engine: 'wasm' | 'fallback' | 'auto'

  // ── Mandate Mode ──────────────────────────────────────────────

  /**
   * How mandate evaluations affect tool calls.
   *
   * - "enforce" — deny means deny (production)
   * - "dry-run" — evaluate + log, but always allow (testing)
   * - "shadow"  — enforce current mandate + evaluate shadowMandate in parallel (policy migration)
   */
  mandateMode: 'enforce' | 'dry-run' | 'shadow'

  /**
   * Candidate mandate to evaluate alongside the real one in shadow mode.
   * Ignored unless mandateMode is "shadow".
   */
  shadowMandate?: CedarMandate

  // ── Subset Proof ──────────────────────────────────────────────

  /**
   * Whether to formally verify mandate ⊆ parent's effective policy at mint time.
   *
   * - "required" — refuse to mint if proof fails (needs PolicySource)
   * - "advisory" — mint anyway, log warning if proof fails
   * - "off"      — skip proof entirely
   */
  subsetProof: 'required' | 'advisory' | 'off'

  /**
   * What to do when proof is required but the prover is inconclusive
   * (timeout, unsupported Cedar features, etc.).
   *
   * - "deny"  — refuse to mint
   * - "allow" — mint with audit warning
   */
  proofFailure: 'deny' | 'allow'

  /** Timeout for subset proof computation (ms). 0 = no timeout. */
  proofTimeoutMs: number

  // ── Enforcement ───────────────────────────────────────────────

  /**
   * What to do when the mandate engine throws an error
   * (NOT a policy deny — an actual engine failure).
   *
   * - "closed" — deny the action (safe)
   * - "open"   — allow the action, log the failure (resilient)
   */
  enforcementFailure: 'closed' | 'open'

  // ── Token Defaults ────────────────────────────────────────────

  /** Default TTL for new tokens (seconds). */
  defaultTtl: number

  /** Maximum TTL a parent can grant (seconds). */
  maxTtl: number

  /** Maximum delegation depth (parent_chain length). */
  maxChainDepth: number

  // ── Policy Source ─────────────────────────────────────────────

  /**
   * Where to get the parent's effective policy for subset proof.
   * Required when subsetProof is "required" or "advisory".
   * null = no deployment-level policy engine.
   */
  policySource: PolicySource | null

  // ── Cross-Domain Trust ────────────────────────────────────────

  /** Trusted issuer public keys: issuer ID → base64 Ed25519 public key. */
  trustedIssuers: Map<string, string>

  /** Accept OVIDs from issuers not in trustedIssuers. */
  allowUnknownIssuers: boolean

  // ── Audit ─────────────────────────────────────────────────────

  /** Path for append-only JSONL audit log. null = disabled. */
  auditLog: string | null

  /** Include full JWT in audit entries. */
  auditIncludeTokens: boolean

  /** SQLite DB path for structured queries/dashboard. null = JSONL only. */
  auditDb: string | null

  /** Dashboard server port (when auditDb is set). */
  dashboardPort: number
}

/** Default configuration — safe, minimal, dry-run: see what would be blocked before enabling enforcement. */
export const DEFAULT_CONFIG: OvidConfig = {
  engine: 'auto',
  mandateMode: 'dry-run',
  subsetProof: 'off',
  proofFailure: 'deny',
  proofTimeoutMs: 5000,
  enforcementFailure: 'closed',
  defaultTtl: 1800,
  maxTtl: 86400,
  maxChainDepth: 5,
  policySource: null,
  trustedIssuers: new Map(),
  allowUnknownIssuers: false,
  auditLog: null,
  auditIncludeTokens: true,
  auditDb: null,
  dashboardPort: 19831,
}

/** Merge partial config with defaults. */
export function resolveConfig(partial?: Partial<OvidConfig>): OvidConfig {
  if (!partial) return { ...DEFAULT_CONFIG }

  const config = { ...DEFAULT_CONFIG, ...partial }

  // Validate: subset proof requires policy source
  if (config.subsetProof !== 'off' && !config.policySource) {
    console.warn(
      '[ovid] subsetProof is "%s" but no policySource configured. Proof will always be inconclusive.',
      config.subsetProof
    )
  }

  // Validate: shadow mode requires shadow mandate
  if (config.mandateMode === 'shadow' && !config.shadowMandate) {
    console.warn('[ovid] mandateMode is "shadow" but no shadowMandate configured. Shadow evaluation skipped.')
  }

  // Apply environment variable overrides (lowest priority)
  return applyEnvOverrides(config)
}

function applyEnvOverrides(config: OvidConfig): OvidConfig {
  const env = process.env

  if (env.OVID_AUDIT_LOG && !config.auditLog) config.auditLog = env.OVID_AUDIT_LOG
  if (env.OVID_AUDIT_DB && !config.auditDb) config.auditDb = env.OVID_AUDIT_DB
  if (env.OVID_MODE && config.mandateMode === DEFAULT_CONFIG.mandateMode) {
    config.mandateMode = env.OVID_MODE as OvidConfig['mandateMode']
  }
  if (env.OVID_DEFAULT_TTL) config.defaultTtl = parseInt(env.OVID_DEFAULT_TTL, 10)
  if (env.OVID_MAX_TTL) config.maxTtl = parseInt(env.OVID_MAX_TTL, 10)
  if (env.OVID_MAX_DEPTH) config.maxChainDepth = parseInt(env.OVID_MAX_DEPTH, 10)
  if (env.OVID_PROOF && config.subsetProof === DEFAULT_CONFIG.subsetProof) {
    config.subsetProof = env.OVID_PROOF as OvidConfig['subsetProof']
  }
  if (env.OVID_PROOF_FAILURE && config.proofFailure === DEFAULT_CONFIG.proofFailure) {
    config.proofFailure = env.OVID_PROOF_FAILURE as OvidConfig['proofFailure']
  }
  if (env.OVID_ENFORCEMENT_FAILURE && config.enforcementFailure === DEFAULT_CONFIG.enforcementFailure) {
    config.enforcementFailure = env.OVID_ENFORCEMENT_FAILURE as OvidConfig['enforcementFailure']
  }

  return config
}
