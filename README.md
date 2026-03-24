# 🪪 OVID-ME

**Cedar policy evaluation for OVID agent mandates.**

OVID-ME reads mandates from verified [OVID](https://github.com/clawdreyhepburn/ovid) tokens and evaluates tool calls against Cedar policies. Three modes: **enforce** (deny means deny), **dry-run** (evaluate + log, always allow), and **shadow** (enforce current + evaluate candidate in parallel for policy migration).

Includes an append-only audit log, SQLite audit database, and a full forensics dashboard.

## Install

```bash
npm install @clawdreyhepburn/ovid-me @clawdreyhepburn/ovid
```

## Quick Example

```typescript
import { generateKeypair, createOvid } from '@clawdreyhepburn/ovid';
import { createAuditLogger, resolveConfig } from '@clawdreyhepburn/ovid-me';

// Create an OVID with a mandate
const keys = await generateKeypair();
const agent = await createOvid({
  issuerKeys: keys,
  issuer: 'orchestrator',
  mandate: {
    rarFormat: 'cedar',
    policySet: 'permit(principal, action == Ovid::Action::"read_file", resource);',
  },
});

// Set up audit logging
const logger = createAuditLogger('./audit.jsonl');

// Log a mandate evaluation decision
logger.logDecision(agent.claims.jti, 'read_file', '/src/main.ts', 'allow', ['policy-read']);
logger.logDecision(agent.claims.jti, 'exec', 'rm -rf /', 'deny', ['policy-safety']);
```

## Configuration

See [docs/CONFIG.md](docs/CONFIG.md) for full configuration reference, including deployment profiles for development, startup, and enterprise environments.

```typescript
import { resolveConfig } from '@clawdreyhepburn/ovid-me';

const config = resolveConfig({
  mandateMode: 'enforce',
  auditLog: '~/.ovid/audit.jsonl',
  auditDb: '~/.ovid/audit.db',
  dashboardPort: 19831,
});
```

## Dashboard

```typescript
import { startDashboard } from '@clawdreyhepburn/ovid-me';

const server = await startDashboard({
  port: 19831,
  dbPath: '~/.ovid/audit.db',
});
// → OVID Dashboard: http://localhost:19831
```

## AuthZEN PDP API

OVID-ME includes an [AuthZEN](https://openid.github.io/authzen/)-compliant Policy Decision Point (PDP) API.

### Quick start

```typescript
import { AuthZenServer } from '@clawdreyhepburn/ovid-me';

const server = new AuthZenServer({
  defaultPolicy: 'permit(principal, action == Ovid::Action::"read_file", resource);',
});
await server.start(19832);
```

### Evaluate a request

```bash
curl -X POST http://localhost:19832/access/v1/evaluation \
  -H "Content-Type: application/json" \
  -d '{
    "subject": { "type": "agent", "id": "agent-47" },
    "action": { "name": "read_file" },
    "resource": { "type": "file", "id": "/src/index.ts" }
  }'
```

Response:
```json
{ "decision": true, "context": { "reason_admin": { "en": "Permitted by mandate" } } }
```

### Batch evaluation

```bash
curl -X POST http://localhost:19832/access/v1/evaluations \
  -H "Content-Type: application/json" \
  -d '{
    "evaluations": [
      { "subject": { "type": "agent", "id": "a1" }, "action": { "name": "read_file" }, "resource": { "type": "file", "id": "/src/index.ts" } },
      { "subject": { "type": "agent", "id": "a1" }, "action": { "name": "exec" }, "resource": { "type": "command", "id": "rm -rf /" } }
    ]
  }'
```

### Spec Compliance

OVID-ME implements the AuthZEN Authorization API 1.0 with the following coverage:

| Feature | Status |
|---------|--------|
| Access Evaluation API (Section 6) | ✅ Full |
| Access Evaluations API (Section 7) | ✅ Full (defaults, semantics) |
| PDP Metadata (Section 9) | ✅ Full |
| Request Identification | ✅ Full |
| Search APIs (Section 8) | ❌ Not implemented |

Search APIs (`/access/v1/search/subjects`, `/search/resources`, `/search/actions`) require reverse policy analysis ("who can access X?") which is non-trivial with Cedar's forward-evaluation model. Contributions welcome.

### Mandate sources

The server resolves mandates in priority order:
1. **Inline** — `context.authorization_details` in the request body
2. **Token** — `context.ovid_token` (planned, not yet implemented)
3. **Default policy** — configured at server startup

## Two-Layer Enforcement Model

OVID-ME is one half of a two-layer authorization stack. Both layers must allow a tool call for it to proceed:

| Layer | What it enforces | Who defines it |
|-------|-----------------|----------------|
| **[Carapace](https://github.com/clawdreyhepburn/carapace)** | Deployment ceiling — what tools are allowed at all | The human, via Cedar policies |
| **OVID-ME** | Parent mandate — what the spawning agent delegated | The parent agent, via OVID JWT |

Carapace runs on every `before_tool_call` hook as the human's hard limit. OVID-ME evaluates the mandate embedded in the agent's OVID token. A sub-agent with a broad mandate can't exceed the deployment ceiling, and a permissive deployment can't override a narrow mandate.

### PolicySource integration

Carapace implements the `PolicySource` interface (`getEffectivePolicy(principal)`), which OVID-ME can query at **mandate issuance time** to verify that a new mandate is a subset of the deployment ceiling. This prevents issuing mandates that would always be blocked — catching policy conflicts at delegation time rather than at enforcement time.

## Related Projects

- [`@clawdreyhepburn/ovid`](https://github.com/clawdreyhepburn/ovid) — cryptographic identity for AI agents (Ed25519 JWTs, delegation chains, mandate embedding)
- [`@clawdreyhepburn/carapace`](https://github.com/clawdreyhepburn/carapace) — deployment-level Cedar policy enforcement via OpenClaw's `before_tool_call` hook

## License

Apache-2.0
