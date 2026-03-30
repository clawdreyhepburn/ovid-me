<p align="center">
  <h1 align="center">🔒 OVID-ME</h1>
  <p align="center"><strong>Mandate evaluation for delegated agent authority.</strong></p>
  <p align="center">
    When Agent A spawns Agent B with narrower permissions, OVID-ME is the thing that actually enforces those permissions at tool-call time.
  </p>
  <p align="center">
    <a href="#the-problem">The Problem</a> •
    <a href="#the-model">The Model</a> •
    <a href="#how-it-works">How It Works</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#api">API</a> •
    <a href="#authzen-pdp">AuthZEN PDP</a> •
    <a href="#two-layer-enforcement">Two-Layer Enforcement</a> •
    <a href="#related-work">Related Work</a>
  </p>
</p>

---

## The Problem

Agent delegation is broken.

When a primary agent spawns a sub-agent, the sub-agent typically inherits the parent's full credentials — same API keys, same OAuth tokens, same tool access. A helpdesk agent that spawns a "check Okta attributes" sub-agent has inadvertently created something with the power to reconfigure Active Directory. The permissions don't narrow. The context does.

Authority moves across hops, but nothing in the system ensures that scope narrows as work gets delegated. OAuth Token Exchange ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)) can express pairwise delegation, but it wasn't built for multi-hop agent chains. It doesn't require stepwise scope narrowing. It doesn't bind tokens to specific transactions. It doesn't give you the auditability you need when the fifth agent in a chain does something the first agent never intended.

OVID-ME is our answer to: **how do you actually enforce attenuated permissions at every hop?**

## The Model

OVID-ME builds on three ideas that already exist in standards — it just combines them for the agent delegation use case:

### 1. SPIFFE-style trust: the spawner is the attestor

In [SPIFFE](https://spiffe.io/), workload identity is rooted in the platform, not in shared secrets. OVID applies the same model to agents: the thing that created a sub-agent is the thing that vouches for it. Trust is cryptographic (Ed25519 signatures) and verifiable without a central authority.

Each agent gets an [OVID token](https://github.com/clawdreyhepburn/ovid) — a signed JWT that says who it is, who created it, what it's allowed to do, and when it expires. The chain is walkable back to the human. No ambient authority. No credential sharing.

### 2. OAuth Token Exchange + RAR: scope narrows at every hop

When an agent delegates to a sub-agent, it performs the equivalent of an [OAuth Token Exchange](https://www.rfc-editor.org/rfc/rfc8693) — but instead of exchanging for flat scopes, it issues an OVID with structured [Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396) (RFC 9396) in the `authorization_details` claim.

These aren't vague scope strings like `jira:read`. They're Cedar policies — executable, auditable, formally verifiable authorization rules:

```
permit(
  principal,
  action == Okta::Action::"read_attribute",
  resource == Okta::UserAttr::"title"
);
```

**Lifetime can only shorten.** A child token can't outlive its parent. **Permissions can only narrow.** A child mandate must be a provable subset of the parent's effective policy. OVID-ME enforces both constraints — the first at issuance time, the second at evaluation time.

This is the "stepwise scope narrowing" that's missing from raw RFC 8693, and it's what [Transaction Tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/) are reaching toward for workloads. OVID-ME makes it concrete for agents.

### 3. Cedar: real policy evaluation, not string matching

The mandate inside each OVID token is a Cedar policy set. [Cedar](https://www.cedarpolicy.com/) is Amazon's authorization language — deterministic, analyzable, built for exactly this kind of structured policy evaluation.

OVID-ME evaluates these mandates against tool calls using the Cedar WASM engine (with a strict-mode fallback parser). Default-deny semantics. Forbid overrides permit. No ambiguity.

## How It Works

```
Human
  │ "resolve the support ticket"
  ▼
Primary Agent (OVID: full mandate)
  │
  │ issues narrower OVID via token exchange
  ▼
Sub-Agent (OVID: can only read Okta attributes)
  │
  │ calls tool: read_attribute("title")
  ▼
OVID-ME evaluates:
  ├─ Verify OVID signature chain ✓
  ├─ Extract Cedar mandate from authorization_details ✓
  ├─ Evaluate: does mandate permit this action? ✓
  └─ Decision: ALLOW
  
  │ calls tool: update_security_settings()
  ▼
OVID-ME evaluates:
  ├─ Verify OVID signature chain ✓
  ├─ Extract Cedar mandate from authorization_details ✓
  ├─ Evaluate: does mandate permit this action? ✗
  └─ Decision: DENY → escalate to parent
```

**Three modes:**

| Mode | Behavior | Use case |
|------|----------|----------|
| **enforce** | Deny means deny | Production |
| **dry-run** | Evaluate + log, always allow | Testing, onboarding |
| **shadow** | Enforce current + evaluate candidate | Policy migration |

**Subset proof at issuance time:** When a parent issues an OVID to a child, OVID-ME can verify (via SMT solver or string analysis) that the child's mandate is a provable subset of the parent's effective policy. Mint fails if the child would get more authority than the parent has. This catches policy errors at delegation time, not at enforcement time.

## Quick Start

### Install

```bash
npm install @clawdreyhepburn/ovid-me @clawdreyhepburn/ovid
```

### Evaluate a mandate

```typescript
import { generateKeypair, createOvid } from '@clawdreyhepburn/ovid';
import { MandateEngine } from '@clawdreyhepburn/ovid-me';

// Parent creates a sub-agent with a narrow mandate
const keys = await generateKeypair();
const subAgent = await createOvid({
  issuerKeys: keys,
  issuer: 'primary-agent',
  mandate: {
    rarFormat: 'cedar',
    policySet: `permit(
      principal,
      action == Ovid::Action::"read_file",
      resource
    ) when { resource.path like "/src/*" };`,
  },
});

// Evaluate tool calls against the mandate
const engine = new MandateEngine({ mandateMode: 'enforce' });
const mandate = subAgent.claims.authorization_details[0];

// This is allowed
const r1 = await engine.evaluate(subAgent.claims.jti, mandate, {
  action: 'read_file',
  resource: '/src/main.ts',
});
// → { decision: 'allow', mode: 'enforce' }

// This is denied — not in the mandate
const r2 = await engine.evaluate(subAgent.claims.jti, mandate, {
  action: 'exec',
  resource: 'rm -rf /',
});
// → { decision: 'deny', mode: 'enforce', reason: 'no matching permit' }
```

### Configuration

```typescript
import { resolveConfig } from '@clawdreyhepburn/ovid-me';

const config = resolveConfig({
  mandateMode: 'enforce',    // 'enforce' | 'dry-run' | 'shadow'
  engine: 'auto',            // 'wasm' | 'fallback' | 'auto'
  subsetProof: 'advisory',   // 'required' | 'advisory' | 'off'
  auditLog: '~/.ovid/audit.jsonl',
  auditDb: '~/.ovid/audit.db',
  dashboardPort: 19831,
});
```

See [docs/CONFIG.md](docs/CONFIG.md) for deployment profiles (development, startup, enterprise).

## API

### MandateEngine

The core evaluation engine. Wraps Cedar evaluation with mode-aware behavior, audit logging, and optional subset proofs.

```typescript
const engine = new MandateEngine(config?);
const result = await engine.evaluate(agentJti, mandate, { action, resource, context? });
```

### AuditLogger

Append-only JSONL audit log + optional SQLite database for structured queries.

```typescript
import { createAuditLogger } from '@clawdreyhepburn/ovid-me';

const logger = createAuditLogger('./audit.jsonl');
logger.logDecision(agentJti, action, resource, decision, matchedPolicies);
```

### Forensics Dashboard

```typescript
import { startDashboard } from '@clawdreyhepburn/ovid-me';

const server = await startDashboard({
  port: 19831,
  dbPath: '~/.ovid/audit.db',
});
// → OVID Dashboard: http://localhost:19831
```

## AuthZEN PDP

OVID-ME includes an [AuthZEN](https://openid.github.io/authzen/)-compliant Policy Decision Point API, so you can integrate it with any authorization architecture that speaks the OpenID AuthZEN protocol.

```typescript
import { AuthZenServer } from '@clawdreyhepburn/ovid-me';

const server = new AuthZenServer({
  defaultPolicy: 'permit(principal, action == Ovid::Action::"read_file", resource);',
});
await server.start(19832);
```

```bash
# Single evaluation
curl -X POST http://localhost:19832/access/v1/evaluation \
  -H "Content-Type: application/json" \
  -d '{
    "subject": { "type": "agent", "id": "agent-47" },
    "action": { "name": "read_file" },
    "resource": { "type": "file", "id": "/src/index.ts" }
  }'
# → { "decision": true }

# Batch evaluation
curl -X POST http://localhost:19832/access/v1/evaluations \
  -H "Content-Type: application/json" \
  -d '{
    "evaluations": [
      { "subject": {"type":"agent","id":"a1"}, "action": {"name":"read_file"}, "resource": {"type":"file","id":"/src/index.ts"} },
      { "subject": {"type":"agent","id":"a1"}, "action": {"name":"exec"}, "resource": {"type":"command","id":"rm -rf /"} }
    ]
  }'
```

| AuthZEN Feature | Status |
|---------|--------|
| Access Evaluation API (§6) | ✅ |
| Access Evaluations API (§7) | ✅ |
| PDP Metadata (§9) | ✅ |
| Search APIs (§8) | ❌ (requires reverse policy analysis) |

## Two-Layer Enforcement

OVID-ME is one half of a two-layer authorization stack:

```
Tool call arrives
       │
       ▼
┌─────────────┐
│  Carapace   │  ← Human's ceiling. Binary allow/deny.
│  (layer 1)  │     "No agent may ever call rm."
└──────┬──────┘
       │ allowed?
       ▼
┌─────────────┐
│  OVID-ME    │  ← Parent's mandate. Cedar evaluation.
│  (layer 2)  │     "This agent may only read /src/*."
└──────┬──────┘
       │ allowed?
       ▼
    Tool runs
```

| Layer | What it enforces | Who defines it | Runs when |
|-------|-----------------|----------------|-----------|
| [Carapace](https://github.com/clawdreyhepburn/carapace) | Deployment ceiling — what's allowed at all | The human | Every tool call |
| OVID-ME | Parent mandate — what the spawner delegated | The parent agent | Every tool call |

Both must allow. A sub-agent with a broad mandate can't exceed the human's ceiling. A permissive deployment can't override a narrow mandate.

Carapace implements the `PolicySource` interface, which OVID-ME queries at mandate issuance time to verify new mandates are a subset of the deployment ceiling. Policy conflicts are caught at delegation time, not at enforcement time.

## Related Work

OVID-ME is informed by and builds on:

- **[SPIFFE](https://spiffe.io/)** — workload identity model (the spawner is the attestor)
- **[OAuth Token Exchange (RFC 8693)](https://www.rfc-editor.org/rfc/rfc8693)** — pairwise delegation
- **[Rich Authorization Requests (RFC 9396)](https://www.rfc-editor.org/rfc/rfc9396)** — structured `authorization_details` claims
- **[Transaction Tokens (draft-ietf-oauth-transaction-tokens)](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/)** — scope-narrowing across trust domains
- **[Cedar](https://www.cedarpolicy.com/)** — deterministic, analyzable policy evaluation
- **[AuthZEN](https://openid.github.io/authzen/)** — interoperable authorization API
- **[OVID](https://github.com/clawdreyhepburn/ovid)** — cryptographic agent identity (Ed25519 JWTs, delegation chains)
- **[Carapace](https://github.com/clawdreyhepburn/carapace)** — deployment-level Cedar policy enforcement


## License

Apache-2.0
