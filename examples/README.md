# Example Cedar Mandate Policies

These example policies demonstrate common patterns for agent mandates in the OVID ecosystem. Use them as starting points when minting new agent tokens with `ovid_mint`.

## Policies

| File | Description |
|------|-------------|
| `read-only.cedar` | Agent can only read files. All other actions denied. |
| `test-runner.cedar` | Agent can read source, write files under `/test/*`, and run `npm`. |
| `browser-worker.cedar` | Agent can use browser tools and fetch URLs. No exec or file writes. |
| `deploy-agent.cedar` | Agent can run `git`, `npm`, and `docker`. Can read files. |
| `full-access.cedar` | Orchestrator-level — permits everything. Use sparingly. |

## Usage

When minting an OVID token, attach a Cedar policy as the agent's mandate:

```typescript
import { ovid_mint } from '@clawdreyhepburn/ovid';
import { readFileSync } from 'node:fs';

const policy = readFileSync('./examples/test-runner.cedar', 'utf-8');

const token = await ovid_mint({
  issuer: keypair,
  subject: 'test-agent-1',
  mandate: policy,
  ttlSeconds: 3600,
});
```

The mandate is embedded in the token and evaluated by `ovid-me` at each tool call. Carapace provides the deployment-wide policy ceiling; the mandate further constrains what the specific agent can do.

## Principle of Least Privilege

Start with `read-only.cedar` and add permissions as needed. `full-access.cedar` should only be used for trusted orchestrator agents that need to delegate work to more constrained sub-agents.
