# Design Doc: AuthZEN Search API for OVID-ME

**Author:** Clawdrey Hepburn
**Date:** March 23, 2026
**Status:** Proposal

## Problem

AuthZEN 1.0 (Section 8) defines three Search APIs:

- **Subject Search**: "Who can `read_file` on `/src/index.ts`?"
- **Resource Search**: "What can `agent-47` `read_file` on?"
- **Action Search**: "What can `agent-47` do to `/src/index.ts`?"

These are reverse queries — instead of "is this specific request allowed?" they ask "what's the universe of allowed things?" OVID-ME currently only answers forward evaluation queries. This doc proposes how to add search.

## Why This Is Hard

Cedar is a forward-evaluation engine. You give it a principal, action, and resource, and it tells you allow or deny. There's no built-in "enumerate all allowed principals" operation.

The naive approach — iterate over every possible subject/resource/action and evaluate each one — doesn't scale. We need something smarter.

## Proposed Approach: Policy Analysis + Bounded Enumeration

### Core Insight

OVID mandates are small. A typical agent mandate has 2-10 Cedar policy statements. We can analyze the policy text structurally to extract the answer set directly, rather than brute-forcing evaluations.

### Architecture

```
                    +-------------------+
  AuthZEN Search    |  Search Analyzer  |
  Request --------> |                   |
                    |  1. Parse policies |
                    |  2. Extract sets   |-----> AuthZEN Search
                    |  3. Intersect      |       Response
                    |  4. Filter         |
                    +-------------------+
                            |
                    uses EvaluateRequest
                    for edge cases
```

### Algorithm

#### Step 1: Parse the Cedar policy set

Reuse the existing `parsePolicies()` infrastructure from `evaluate.ts`. Each parsed policy gives us:

```typescript
interface ParsedPolicy {
  effect: 'permit' | 'forbid';
  actions: string[] | null;      // null = wildcard
  resourceGlob: string | null;   // null = wildcard
}
```

#### Step 2: Build candidate sets from policy structure

**For Subject Search** ("who can do X on Y?"):

OVID mandates are per-agent — the mandate is already scoped to one principal. Cedar policies in mandates use `principal` (wildcard) in the head, meaning "whoever holds this token." So the answer to "who can read_file on /src/index.ts?" is:

1. Query the audit database for all known agent JTIs
2. For each agent, retrieve their mandate (from audit log or token cache)
3. Evaluate the specific (agent, action, resource) triple
4. Return agents where the decision is `allow`

This is bounded enumeration, but scoped to *known agents* from audit history — not infinite.

**For Resource Search** ("what can agent X do action Y on?"):

1. Parse the agent's mandate
2. Collect all `permit` policies matching the requested action
3. Extract `resource.path like "..."` globs from `when` clauses
4. Subtract resources matching any `forbid` for the same action
5. Return the glob patterns as results (not individual files)

The key insight: we return *patterns*, not enumerated resources. A response like `[{ type: "file", id: "/src/*" }]` is more useful than listing every file. The spec allows `properties` on returned entities, so we can include `{ "pattern": "/src/*", "match_type": "glob" }`.

**For Action Search** ("what can agent X do to resource Y?"):

1. Parse the agent's mandate
2. For each unique action in the policy set, evaluate (agent, action, resource)
3. Return actions where the decision is `allow`

This is small — the action space is bounded by what's in the schema (currently 8 actions).

#### Step 3: Apply forbid filtering

After collecting the candidate set from `permit` policies, we must subtract anything that would be denied by `forbid` policies. For exact action matches this is straightforward. For wildcard actions + resource globs, we need glob intersection/subtraction.

Glob subtraction is the hard part. If a permit says `resource.path like "/src/*"` and a forbid says `resource.path like "/src/secrets/*"`, the result is `/src/*` minus `/src/secrets/*`. We can represent this as:

```typescript
interface ResourcePattern {
  include: string;   // glob pattern
  exclude: string[]; // subtracted patterns
}
```

#### Step 4: Pagination

AuthZEN Section 8.2 defines pagination. For subject and action search, result sets are small enough to return in one page. For resource search (which returns patterns), pagination is unlikely to be needed, but we should support it:

```typescript
interface SearchResponse {
  page?: { count: number; total: number; next?: string };
  results: Array<{ type: string; id: string; properties?: Record<string, unknown> }>;
}
```

### Data Dependencies

Search needs access to data that the current evaluation path doesn't:

| Search Type | Data Needed | Source |
|-------------|------------|--------|
| Subject | All known agents + their mandates | Audit DB |
| Resource | Agent's mandate | Token/audit DB |
| Action | Agent's mandate + schema actions | Token/audit DB + schema |

The audit database (`~/.ovid/audit.db`) already stores agent JTIs, actions, and resources. We'd need to also store the mandate policy text per agent (or a reference to retrieve it).

**New audit DB column:** `mandate_policy TEXT` on the decisions table, storing the raw Cedar text used for evaluation. This enables subject search without needing to re-verify tokens.

### WASM vs Fallback

For the fallback engine, we can do structural analysis directly on `ParsedPolicy` objects — no evaluation needed for resource and action search.

For the WASM engine, we can't introspect Cedar's internal policy representation. Options:

1. **Parse the Cedar text ourselves** (same as fallback) for search, use WASM only for forward evaluation
2. **Use Cedar's partial evaluation** if Cedarling exposes it — Cedar supports residual policies that could answer "what resources match?"

Option 1 is pragmatic and works today. Option 2 is better but depends on upstream Cedarling features.

**Recommendation:** Option 1. Parse policy text for search, WASM for forward eval. The policy text is always available (it's in the JWT).

### API Design

```
POST /access/v1/search/subjects
POST /access/v1/search/resources
POST /access/v1/search/actions
```

Per the AuthZEN spec, the search request omits the `id` of the entity being searched for, but includes the other entities:

```typescript
// Subject search: who can read /src/index.ts?
{
  subject: { type: "agent" },         // type only, no id
  action: { name: "read_file" },
  resource: { type: "file", id: "/src/index.ts" }
}

// Resource search: what can agent-47 read?
{
  subject: { type: "agent", id: "agent-47" },
  action: { name: "read_file" },
  resource: { type: "file" }          // type only, no id
}

// Action search: what can agent-47 do to /src/index.ts?
{
  subject: { type: "agent", id: "agent-47" },
  action: {},                          // name omitted
  resource: { type: "file", id: "/src/index.ts" }
}
```

### Mandate Resolution for Search

Forward evaluation gets the mandate from the request context. Search needs mandates for *multiple* agents (subject search) or a *specific* agent (resource/action search).

Three sources, in priority order:

1. **Request context** — `context.authorization_details` or `context.ovid_token` (resource/action search)
2. **Audit database** — look up stored mandates by agent JTI (subject search)
3. **Default policy** — server's configured default (all search types)

For subject search, we MUST have the audit DB. Without it, we have no population of agents to search over.

### Implementation Plan

**Phase 1: Action Search** (simplest)
- Parse mandate, extract unique actions from schema + policy
- Evaluate each (subject, action, resource) triple
- Return allowed actions
- Estimated: ~100 lines, no new dependencies

**Phase 2: Resource Search** (moderate)
- Parse mandate, extract resource globs from permits
- Apply forbid subtraction
- Return patterns with glob metadata
- Estimated: ~200 lines, needs glob intersection logic

**Phase 3: Subject Search** (hardest)
- Add `mandate_policy` column to audit DB
- Query distinct agents from audit history
- Evaluate (agent, action, resource) for each
- Paginate results
- Estimated: ~300 lines, needs DB migration

### Open Questions

1. **Should resource search return glob patterns or attempt to enumerate?** Patterns are more honest (we don't know your filesystem), but the AuthZEN spec examples show concrete resource IDs. Recommendation: return patterns with `properties.pattern_type: "cedar_like"` to indicate they're match patterns.

2. **How fresh must subject search results be?** The audit DB only knows about agents that have been evaluated before. A newly minted agent with no evaluations won't appear. Should we document this limitation or add a registration mechanism?

3. **Should we support Cedar partial evaluation?** If Cedarling exposes Cedar's partial evaluation API in a future version, we could get exact answers for resource search instead of pattern approximations. Worth tracking but not blocking.

4. **Result consistency guarantee**: AuthZEN Section 8.1 says "any result from a Search API, when subsequently used in an Access Evaluation API call, SHOULD result in a `decision: true` response." We can guarantee this for action search (exact evaluation). For resource search with glob patterns, a specific resource matching the pattern SHOULD be allowed but edge cases with overlapping forbids could violate this. Document as a known limitation.

### Estimated Effort

| Phase | Complexity | Lines | Tests |
|-------|-----------|-------|-------|
| Action Search | Low | ~100 | ~8 |
| Resource Search | Medium | ~200 | ~12 |
| Subject Search | High | ~300 | ~10 |
| DB migration | Low | ~30 | ~4 |
| **Total** | | **~630** | **~34** |

### Decision

Implement in three phases. Action search first (quick win, unblocks "what can this agent do?" dashboard feature). Resource search second. Subject search last (needs DB changes).

All three can share a `PolicyAnalyzer` class that wraps `parsePolicies()` with set extraction methods.
