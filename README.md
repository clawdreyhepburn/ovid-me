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

## Related Projects

- [`@clawdreyhepburn/ovid`](https://github.com/clawdreyhepburn/ovid) — cryptographic identity (token creation, verification, keypairs)
- [`@clawdreyhepburn/carapace`](https://github.com/clawdreyhepburn/carapace) — deployment-level policy ceiling (binary allow/deny, implements PolicySource so OVID-ME can query it)

## License

Apache-2.0
