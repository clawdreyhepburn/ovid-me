# OVID-ME Configuration Reference

OVID-ME is designed to work out of the box for a solo developer and scale to enterprise multi-domain deployments. All configuration is deployment-wide — per-agent behavior is expressed through mandates, not config overrides.

## Quick Start

Zero config gets you working tokens with no enforcement:

```typescript
import { createOvid, verifyOvid, generateKeypair } from '@clawdreyhepburn/ovid'
import { resolveConfig } from '@clawdreyhepburn/ovid-me'

const root = await generateKeypair()
const child = await generateKeypair()

const ovid = await createOvid({
  issuerKey: root.privateKey,
  claims: {
    iss: 'my-orchestrator',
    sub: 'my-worker',
    agent_pub: child.publicKeyBase64,
    mandate: {
      type: 'agent_mandate', rarFormat: 'cedar',
      policySet: 'permit(principal, action, resource) when { resource.path like "/safe/*" };'
    }
  }
})
```

Everything below is opt-in.

## Full Configuration

```typescript
import { OvidMeConfig } from '@clawdreyhepburn/ovid-me'

const config: OvidConfig = {

  // ┌─────────────────────────────────────────────┐
  // │  MANDATE MODE                                │
  // │  How mandate evaluations affect tool calls   │
  // └─────────────────────────────────────────────┘

  // "enforce" — mandate decisions are real. Deny means deny.
  // "dry-run" — evaluate mandates, log decisions, but always allow.
  //             Use this when testing mandates before deploying them.
  // "shadow"  — enforce the current mandate AND evaluate a candidate
  //             mandate in parallel. Candidate results are logged only.
  //             Use this when tightening an existing mandate.
  mandateMode: "dry-run",  // default: "dry-run"
  // Start with dry-run to understand your agents' access patterns.
  // Switch to enforce when confident.

  // Shadow mode only: candidate mandate to evaluate alongside the real one.
  // Ignored unless mandateMode is "shadow".
  shadowMandate: {
    type: "agent_mandate", rarFormat: "cedar",
    policySet: 'permit(principal, action == Ovid::Action::"read_file", resource);'
  },


  // ┌─────────────────────────────────────────────┐
  // │  SUBSET PROOF                                │
  // │  Verify mandate ⊆ parent's effective policy  │
  // └─────────────────────────────────────────────┘

  // Whether to formally verify that a child's mandate is a subset
  // of the issuing parent's effective permissions.
  //
  // "required" — refuse to mint if proof fails or is inconclusive.
  //              Strongest guarantee. Requires a PolicySource.
  // "advisory" — mint anyway if proof fails, but log a warning.
  //              Good for rollout: see what would fail before enforcing.
  // "off"      — skip proof entirely. Just sign the token.
  //              Fastest. Use for development or when you trust the orchestrator.
  subsetProof: "off",  // default: "off"

  // What happens when proof is required but the prover can't determine
  // the result (timeout, unsupported Cedar features, complexity limit).
  // This is separate from subsetProof because even with proofs enabled,
  // the prover may hit edge cases it can't reason about.
  //
  // "deny"  — refuse to mint. Safe default for high-security deployments.
  // "allow" — mint with a warning in the audit log. Keeps things running
  //           while you investigate why the proof was inconclusive.
  proofFailure: "deny",  // default: "deny"

  // Timeout for subset proof computation (milliseconds).
  // Cedar subset proofs can be expensive for complex policies.
  // Set to 0 for no timeout (not recommended in production).
  proofTimeoutMs: 5000,  // default: 5000


  // ┌─────────────────────────────────────────────┐
  // │  ENFORCEMENT                                 │
  // │  Runtime mandate evaluation behavior         │
  // └─────────────────────────────────────────────┘

  // What happens when the mandate engine encounters an error
  // (malformed policy, missing context, engine crash).
  // This is NOT about "the policy says deny" — that's normal operation.
  // This is about "the policy engine threw an exception."
  //
  // "closed" — deny the action. Safe but may stop agents unexpectedly.
  // "open"   — allow the action, log the failure. Risky but resilient.
  enforcementFailure: "closed",  // default: "closed"


  // ┌─────────────────────────────────────────────┐
  // │  TOKEN DEFAULTS                              │
  // │  Defaults for newly minted OVIDs             │
  // └─────────────────────────────────────────────┘

  // Default time-to-live for new tokens (seconds).
  // Short-lived tokens are the primary revocation mechanism.
  defaultTtl: 1800,  // default: 1800 (30 minutes)

  // Maximum TTL a parent can grant to a child.
  // Prevents "forever tokens" regardless of what the orchestrator requests.
  maxTtl: 86400,  // default: 86400 (24 hours)

  // Maximum delegation depth (length of parent_chain).
  // Limits how deep the agent tree can grow.
  // 1 = only direct children of root. 5 = five levels of sub-agents.
  maxChainDepth: 5,  // default: 5


  // ┌─────────────────────────────────────────────┐
  // │  POLICY SOURCE                               │
  // │  Where to get the parent's effective policy   │
  // └─────────────────────────────────────────────┘

  // Interface for retrieving the effective Cedar policy set for a
  // given principal. Required when subsetProof is "required" or "advisory".
  //
  // OVID doesn't know or care what implements this. Carapace, a static
  // file, a remote policy server, or a custom adapter all work.
  //
  // Set to null if you don't have a deployment-level policy engine.
  policySource: null,  // default: null

  // Example: Carapace adapter
  // policySource: new CarapacePolicySource({ configPath: '~/.openclaw/openclaw.json' }),
  //
  // Example: static file
  // policySource: new FilePolicySource({ path: './policies/ceiling.cedar' }),
  //
  // Example: remote
  // policySource: new RemotePolicySource({ url: 'https://policy.internal/api/v1/effective' }),


  // ┌─────────────────────────────────────────────┐
  // │  CROSS-DOMAIN TRUST                          │
  // │  Accepting OVIDs from other deployments      │
  // └─────────────────────────────────────────────┘

  // Map of trusted issuer IDs to their Ed25519 public keys (base64).
  // Used when verifying OVIDs that originated from a different deployment.
  // The root of the parent_chain must match a trusted issuer.
  trustedIssuers: new Map([
    // ["partner-orchestrator", "base64-encoded-public-key-here"],
  ]),

  // Whether to accept OVIDs signed by issuers not in trustedIssuers.
  // true  = accept any valid signature (open federation, development)
  // false = reject unknown issuers (production, enterprise)
  allowUnknownIssuers: false,  // default: false


  // ┌─────────────────────────────────────────────┐
  // │  AUDIT                                       │
  // │  Logging and forensics                       │
  // └─────────────────────────────────────────────┘

  // File path for append-only JSONL audit log.
  // Every issuance and mandate evaluation is recorded.
  // null = audit logging disabled.
  auditLog: null,  // default: null

  // Record full JWT text in audit entries.
  // true  = full forensic trail (larger log, but you can replay everything)
  // false = metadata only (smaller, but you lose the ability to re-verify)
  auditIncludeTokens: true,  // default: true

  // SQLite database path for structured audit queries and dashboard.
  // Enables the forensics dashboard, anomaly detection, and complex queries.
  // null = JSONL only (or no audit if auditLog is also null).
  auditDb: null,  // default: null

  // Dashboard server port. Only used when auditDb is set.
  dashboardPort: 19831,  // default: 19831
}
```

## Deployment Profiles

### Development / Hobbyist

```typescript
const config: Partial<OvidConfig> = {
  mandateMode: "dry-run",
  subsetProof: "off",
  defaultTtl: 3600,
  allowUnknownIssuers: true,
}
```

Tokens work, nothing blocks, logs show what would happen. Good for learning and experimentation.

### Startup / Small Team

```typescript
const config: Partial<OvidConfig> = {
  mandateMode: "enforce",
  subsetProof: "advisory",
  enforcementFailure: "closed",
  auditLog: "~/.ovid/audit.jsonl",
  defaultTtl: 1800,
}
```

Mandates are enforced. Subset proofs log warnings but don't block. Audit trail for debugging. Good for teams that want guardrails without operational overhead.

### Enterprise / Multi-Domain

```typescript
const config: Partial<OvidConfig> = {
  mandateMode: "enforce",
  subsetProof: "required",
  proofFailure: "deny",
  proofTimeoutMs: 10000,
  enforcementFailure: "closed",
  auditLog: "/var/log/ovid/audit.jsonl",
  auditIncludeTokens: true,
  auditDb: "/var/lib/ovid/audit.db",
  defaultTtl: 900,
  maxTtl: 3600,
  maxChainDepth: 3,
  allowUnknownIssuers: false,
  trustedIssuers: new Map([
    ["production-orchestrator", "..."],
    ["staging-orchestrator", "..."],
  ]),
}
```

Full enforcement, mandatory proofs, fail-closed everything, short TTLs, restricted depth, explicit trust. Compliance-ready.

### Shadow Mode (Testing Policy Changes)

```typescript
const config: Partial<OvidConfig> = {
  mandateMode: "shadow",
  shadowMandate: {
    type: "agent_mandate", rarFormat: "cedar",
    policySet: `
      // Tighter mandate: remove exec permission
      permit(principal, action == Ovid::Action::"read_file", resource);
      permit(principal, action == Ovid::Action::"write_file", resource)
        when { resource.path like "/test/*" };
      forbid(principal, action, resource);
    `
  },
  auditLog: "~/.ovid/shadow-audit.jsonl",
}
```

Run for a day, then query: `grep '"shadow_decision":"deny"' shadow-audit.jsonl` to see what the tighter mandate would have blocked.

## PolicySource Interface

```typescript
interface PolicySource {
  /**
   * Return the effective Cedar policy set for the given principal.
   * 
   * The returned string must be valid Cedar policy text.
   * It represents the complete set of permissions the principal
   * currently has from the deployment-level policy engine.
   *
   * @param principal - The agent ID (matches the `iss` claim of the OVID being minted)
   * @returns Cedar policy text, or null if the principal has no effective policy
   */
  getEffectivePolicy(principal: string): Promise<string | null>
}
```

### Implementing a PolicySource

**For Carapace:**
```typescript
class CarapacePolicySource implements PolicySource {
  async getEffectivePolicy(principal: string): Promise<string | null> {
    // Read Cedar policies from Carapace's policy directory
    // Filter to policies applicable to this principal
    // Return as Cedar text
  }
}
```

**For a static file (simplest):**
```typescript
class FilePolicySource implements PolicySource {
  constructor(private path: string) {}
  async getEffectivePolicy(_principal: string): Promise<string | null> {
    return readFileSync(this.path, 'utf-8')
  }
}
```

**For a remote policy server:**
```typescript
class RemotePolicySource implements PolicySource {
  constructor(private baseUrl: string) {}
  async getEffectivePolicy(principal: string): Promise<string | null> {
    const res = await fetch(`${this.baseUrl}?principal=${encodeURIComponent(principal)}`)
    if (!res.ok) return null
    return res.text()
  }
}
```

## Environment Variables

For convenience, some settings can be set via environment variables. Programmatic config takes precedence.

| Variable | Maps to | Example |
|----------|---------|---------|
| `OVID_AUDIT_LOG` | `auditLog` | `~/.ovid/audit.jsonl` |
| `OVID_AUDIT_DB` | `auditDb` | `~/.ovid/audit.db` |
| `OVID_MODE` | `mandateMode` | `enforce`, `dry-run`, `shadow` |
| `OVID_DEFAULT_TTL` | `defaultTtl` | `1800` |
| `OVID_MAX_TTL` | `maxTtl` | `86400` |
| `OVID_MAX_DEPTH` | `maxChainDepth` | `5` |
| `OVID_PROOF` | `subsetProof` | `required`, `advisory`, `off` |
| `OVID_PROOF_FAILURE` | `proofFailure` | `deny`, `allow` |
| `OVID_ENFORCEMENT_FAILURE` | `enforcementFailure` | `closed`, `open` |
