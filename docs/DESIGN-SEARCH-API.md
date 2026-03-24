# Design Doc: AuthZEN Search API for OVID-ME

**Author:** Clawdrey Hepburn
**Date:** March 23, 2026
**Status:** Proposal (v2 — rewritten around Cedar partial evaluation)

## Problem

AuthZEN 1.0 (Section 8) defines three Search APIs:

- **Subject Search**: "Who can `read_file` on `/src/index.ts`?"
- **Resource Search**: "What can `agent-47` `read_file` on?"
- **Action Search**: "What can `agent-47` do to `/src/index.ts`?"

These are reverse queries — instead of "is this specific request allowed?" they ask "what's the universe of allowed things?" OVID-ME currently only answers forward evaluation queries. This doc proposes how to add search.

## Key Insight: Cedar Partial Evaluation

Cedar isn't just allow/deny. The `is_authorized_partial` API accepts requests with **unknown** components and returns **residual policies** — simplified Cedar expressions containing only the conditions that still need to be resolved.

Example: "What can agent-47 read?" (resource unknown)

```
Input:
  principal = User::"agent-47"
  action    = Action::"read"
  resource  = <unknown>

Residual output:
  permit(principal, action, resource)
    when { unknown("resource").path like "/src/*" };
  forbid(principal, action, resource)
    when { unknown("resource").path like "/src/secrets/*" };
```

The residuals ARE the search result. They say: "read is allowed on resources with path matching `/src/*`, except those matching `/src/secrets/*`." No enumeration. No approximation. No manual policy parsing. Cedar does the hard work.

This is fundamentally different from brute-force evaluation or structural parsing. Partial evaluation handles the full Cedar language — `unless` clauses, boolean combinators, entity hierarchies, `has` operator, context conditions — all reduced to their simplest form with respect to the unknowns.

## How Partial Evaluation Maps to Each Search Type

### Resource Search: "What can agent-47 read?"

Leave `resource` as unknown. Supply principal and action.

```
Request:
  principal = Ovid::Agent::"agent-47"
  action    = Ovid::Action::"read_file"
  resource  = <unknown>

Response: residual policies describing resource conditions
```

The residuals contain exactly the resource constraints. A permit with `unknown("resource").path like "/src/*"` tells the caller which resources are accessible. A forbid with `unknown("resource").path like "/src/secrets/*"` carves out exceptions.

**AuthZEN response format:**

```json
{
  "results": [
    {
      "type": "Ovid::Resource",
      "id": "*",
      "properties": {
        "conditions": [
          { "effect": "permit", "when": "resource.path like \"/src/*\"" },
          { "effect": "forbid", "when": "resource.path like \"/src/secrets/*\"" }
        ],
        "representation": "cedar_residual"
      }
    }
  ]
}
```

This is more expressive than returning enumerated resource IDs — it returns the actual policy logic, which the caller can evaluate client-side against their resource catalog.

### Action Search: "What can agent-47 do to /src/index.ts?"

Leave `action` as unknown. Supply principal and resource.

```
Request:
  principal = Ovid::Agent::"agent-47"
  action    = <unknown>
  resource  = Ovid::Resource::"/src/index.ts"

Response: residual policies describing action conditions
```

Residuals come back with expressions like `unknown("action") == Ovid::Action::"read_file"` and `unknown("action") == Ovid::Action::"write_file"`. We extract the concrete action values from these expressions and return them.

If we also set resource attributes (e.g., `resource.path = "/src/index.ts"`), the residuals will already have the resource conditions resolved. A forbid on `/src/secrets/*` won't appear because `/src/index.ts` doesn't match it.

**AuthZEN response format:**

```json
{
  "results": [
    { "type": "Action", "id": "read_file" },
    { "type": "Action", "id": "write_file" }
  ]
}
```

### Subject Search: "Who can read /src/index.ts?"

Leave `principal` as unknown. Supply action and resource.

This is the trickiest case. OVID mandates are per-agent — each agent has its own policy set embedded in its JWT. There's no single global policy set to partially evaluate against.

**Approach:** Iterate over known agents (from audit DB), partially evaluate each agent's mandate with the given action and resource, and collect agents where the decision is `allow` (not `unknown`).

This is bounded enumeration, but:
1. The population is finite (agents in audit history)
2. Each evaluation is a full forward eval (principal IS known), so it's fast
3. No partial evaluation needed — it's just `is_authorized` per agent

Partial evaluation doesn't help here because the unknowns are across policy sets, not within one. But the population is small enough that enumeration is fine.

**AuthZEN response format:**

```json
{
  "results": [
    { "type": "Ovid::Agent", "id": "agent-47" },
    { "type": "Ovid::Agent", "id": "agent-12" }
  ]
}
```

## Architecture

```
                         ┌──────────────────────┐
  AuthZEN Search ──────> │    Search Dispatcher  │
  Request                │                       │
                         │  resource search ─────┼──> Cedar partial eval (resource unknown)
                         │  action search ───────┼──> Cedar partial eval (action unknown)
                         │  subject search ──────┼──> Bounded enumeration over audit DB
                         └──────────┬─────────────┘
                                    │
                         ┌──────────▼─────────────┐
                         │   Residual Interpreter  │
                         │                         │
                         │  Parse residual text    │
                         │  Extract conditions     │
                         │  Format AuthZEN response│
                         └─────────────────────────┘
```

## Implementation: Cedar Partial Eval Binary

Cedar's `partially-authorize` CLI command (with `partial-eval` feature flag) already does exactly what we need. We've rebuilt the Cedar CLI with this feature enabled:

```bash
cedar partially-authorize \
  -p mandate.cedar \
  -s schema.cedarschema \
  --entities entities.json \
  -l 'Ovid::Agent::"agent-47"' \
  -a 'Ovid::Action::"read_file"' \
  -f json
```

Omitting `-r` (resource) makes it unknown. The output is the set of residual policies.

### Integration Options

**Option A: Shell out to Cedar CLI** (recommended for v1)
- Already works, already built, already tested
- Parse JSON output to extract residuals
- Latency: ~10-50ms per call (process spawn + eval)
- No new Rust code needed

**Option B: Rust helper binary** (for production)
- Thin Rust binary using `cedar-policy` crate directly with `partial-eval` feature
- Accepts JSON request on stdin, returns residuals on stdout
- Eliminates process spawn overhead for repeated calls
- Could be the same `agent-authz-prover` binary with a `partial-eval` subcommand

**Option C: WASM via Cedarling** (blocked)
- Cedarling doesn't currently expose partial evaluation
- Track upstream: if they add it, this becomes the best option (in-process, no IPC)

### Residual Parsing

Residuals come back as Cedar policy text. We need to parse them into structured data:

```typescript
interface Residual {
  effect: 'permit' | 'forbid';
  conditions: ResidualCondition[];
}

interface ResidualCondition {
  unknown: string;           // "resource", "action", or "principal"
  operator: string;          // "like", "==", "in", "has", etc.
  field?: string;            // "path", "command", etc. (for attribute access)
  value: string | string[];  // the concrete value(s)
  raw: string;               // original Cedar expression for passthrough
}
```

For simple cases (`unknown("action") == Ovid::Action::"read_file"`), we extract the action name directly. For complex cases (`unknown("resource").path like "/src/*" && unknown("resource").path != "/src/secrets/keys"`), we return the raw Cedar expression and let the caller interpret it.

The `raw` field is key: callers who understand Cedar can use residuals directly. Callers who don't can use the structured fields for simple cases and fall back to re-evaluating specific resources against the full policy for complex ones.

## Data Dependencies

| Search Type | Needs | Source |
|-------------|-------|--------|
| Resource | Agent's mandate + Cedar CLI w/ partial-eval | JWT or audit DB |
| Action | Agent's mandate + Cedar CLI w/ partial-eval | JWT or audit DB |
| Subject | All known agents + their mandates | Audit DB |

### Audit DB Changes

Add `mandate_policy TEXT` column to the decisions table. This stores the raw Cedar text used for each evaluation, enabling subject search without re-verifying expired tokens.

```sql
ALTER TABLE decisions ADD COLUMN mandate_policy TEXT;
```

## API Design

```
POST /access/v1/search/subjects
POST /access/v1/search/resources
POST /access/v1/search/actions
```

Per AuthZEN, the search request omits the `id` of the entity being searched for:

```typescript
// Resource search: what can agent-47 read?
{
  subject: { type: "Ovid::Agent", id: "agent-47" },
  action: { name: "read_file" },
  resource: { type: "Ovid::Resource" }   // no id
}

// Action search: what can agent-47 do to /src/index.ts?
{
  subject: { type: "Ovid::Agent", id: "agent-47" },
  action: {},                             // no name
  resource: { type: "Ovid::Resource", id: "/src/index.ts" }
}

// Subject search: who can read /src/index.ts?
{
  subject: { type: "Ovid::Agent" },       // no id
  action: { name: "read_file" },
  resource: { type: "Ovid::Resource", id: "/src/index.ts" }
}
```

## Consistency Guarantee

AuthZEN Section 8.1: "any result from a Search API, when subsequently used in an Access Evaluation API call, SHOULD result in a `decision: true` response."

- **Action search**: Guaranteed. We only return actions that fully resolve to `allow`.
- **Resource search**: Guaranteed for any concrete resource matching the returned conditions, because the residuals are exact — they represent the precise conditions under which Cedar would allow.
- **Subject search**: Guaranteed. We only return agents whose forward evaluation returned `allow`.

Partial evaluation gives us exact answers, not approximations. This is the main advantage over structural parsing.

## Edge Cases

### Multiple unknowns

We could leave both action and resource unknown simultaneously. Cedar handles this — residuals would contain conditions on both. But AuthZEN search APIs only search one dimension at a time, so we don't need this. Worth noting for future extensions.

### Context-dependent policies

Policies that reference `context` (e.g., time-of-day restrictions) will appear in residuals as conditions on context attributes. If context is supplied in the search request, those conditions get resolved. If not, they remain as residuals — which is correct (the search result is conditional on context).

### Empty residuals

If partial evaluation returns a definite `ALLOW` with no residuals, the search result is "everything" (for the searched dimension). If it returns definite `DENY`, the result is empty.

## Implementation Plan

| Phase | What | Complexity | Estimate |
|-------|------|-----------|----------|
| 1 | Action search via Cedar CLI partial-eval | Low | ~150 lines, ~8 tests |
| 2 | Resource search via Cedar CLI partial-eval | Medium | ~200 lines, ~12 tests |
| 3 | Residual parser (structured extraction) | Medium | ~150 lines, ~10 tests |
| 4 | Subject search via audit DB enumeration | Medium | ~200 lines, ~8 tests |
| 5 | Audit DB migration (mandate_policy column) | Low | ~30 lines, ~4 tests |
| 6 | Rust helper binary (optional, replaces CLI shelling) | Medium | ~300 lines, ~6 tests |
| **Total** | | | **~1030 lines, ~48 tests** |

Phase 1 first — it's the simplest and proves out the CLI integration. Phase 6 is optional optimization.

## Relationship to Carapace

Search results from OVID-ME reflect what an agent's **mandate** permits, not what the full deployment allows. In the two-layer enforcement model, [Carapace](https://github.com/clawdreyhepburn/carapace) enforces the deployment ceiling independently. A resource or action returned by OVID-ME search may still be blocked by Carapace at call time.

For callers that need the intersection (what's actually reachable), future work could query Carapace's `PolicySource` to intersect deployment policy with mandate residuals. For now, search results represent the mandate layer only, and the AuthZEN consistency guarantee (Section 8.1) holds within that layer.

## Open Questions

1. **Residual format in AuthZEN response.** The spec doesn't define how to return policy conditions. Our `properties.conditions` approach extends the response schema. Should we propose this as an AuthZEN extension?

2. **Cedar CLI vs Rust binary tradeoff.** CLI shelling is ~10-50ms overhead per call. For a dashboard refreshing search results, this is fine. For high-throughput use, the Rust binary is better. When do we switch?

3. **Cedarling WASM partial-eval.** If Cedarling adds partial evaluation support, we'd get in-process evaluation with zero IPC overhead. Worth tracking upstream.

## Decision

Implement search using Cedar partial evaluation as the primary mechanism. Shell out to the Cedar CLI (rebuilt with `partial-eval` feature) for resource and action search. Use bounded enumeration over the audit DB for subject search. Start with action search (Phase 1) as a proof of concept.
