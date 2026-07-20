# Changelog

## [0.4.4] - 2026-07-20

### Changed
- **Native Cedar engine:** evaluation now uses official `@cedar-policy/cedar-wasm`
  (`isAuthorized`) instead of `@janssenproject/cedarling_wasm`. Same family as
  Carapace 1.0.12+. Cedarling dependency removed.
- **Default `engine` is now `"wasm"`** (was `"auto"`).
- **`engine: "auto"` no longer silent-degrades to the string matcher.** On WASM
  failure both `wasm` and `auto` fail closed (deny) with a clear reason. The
  string matcher remains available only via explicit `engine: "fallback"`.
  Closes the Carapace-class bug where `when`/context policies looked enforced
  but were evaluated by a matcher that cannot see conditions.
- AuthZEN health advertises `cedar_engine: "cedar-wasm"`.

### Fixed
- Request actions not present in the synthesized/external schema are added
  before `isAuthorized` (deny-path probes like unknown `rm_rf` no longer null
  out of WASM).
- External schema namespace wins over policy-detected namespace when rewriting
  bare `Action::` / `Shell::` tokens (Carapace Jans integration).
- Principal type prefers `request.principalType` / schema `Workload` over a
  hardcoded `Agent` (Carapace `principal is Workload` permits).

### Added
- Regression test: when-clause path gating under native WASM (matching deny,
  non-matching allow).

## [0.4.3] - 2026-07-13

### Fixed
- **`AuditDatabase` no longer crashes at module load when the better-sqlite3 native
  binding is missing.** better-sqlite3 ships a native addon that is built/fetched by an
  install script. Hosts that install with `npm --ignore-scripts` (which is what OpenClaw's
  plugin installer does for safety) never get the binding, and the previous top-level
  `import Database from 'better-sqlite3'` threw at load time — taking down any service that
  imported this module before a try/catch could run. better-sqlite3 is now loaded lazily
  inside the `AuditDatabase` constructor via `createRequire` (this package is ESM, so a bare
  `require` is not defined — that itself was a latent trap). A missing binding now throws a
  catchable error with `code = 'OVID_SQLITE_UNAVAILABLE'`, letting callers degrade to
  JSONL-only auditing instead of failing hard. 241/241 tests pass.

## [0.3.2] - 2026-04-19

Carapace end-to-end compatibility ("finding #5 — vocabulary mismatch").

Before this release, OVID-ME could read Carapace's policy text via
`CarapacePolicySource.getEffectivePolicy()` but could not actually
**evaluate** it, because:

  1. The fallback parser rejected `resource == Type::"id"` clauses as
     unsupported syntax.
  2. The WASM engine silently failed to match bare `Action::"X"` or
     `Type::"id"` references against a Cedarling schema declared under
     a named namespace (empty diagnostics, default-deny).
  3. The synthesized Agent + Resource schema didn't admit Carapace's
     custom entity types (`Shell`, `Tool`, `API`, `Workload`).

All three are fixed here. A real Carapace policy (multi-statement,
bare-namespace, typed `resource ==`) now evaluates end-to-end through
both engines and produces correct allow/deny decisions.

### Added
- `EvaluateRequest.resourceType?: string` and
  `EvaluateRequest.principalType?: string`. Callers that work with a
  deployment's custom schema (e.g. Carapace's `Shell`/`Tool`/`API`)
  can name the entity type per request. Absent values fall back to
  the synthesized `<ns>::Agent` and `<ns>::Resource`.
- `EvaluateWithWasmOptions.externalSchema?: Record<string, any>` on
  `evaluateWithWasm`, and `EvaluateAsyncOptions.externalSchema` on
  `evaluateMandateAsync`. Pass the deployment's Cedar schema (e.g.
  parsed `schema.json`) to use it in place of OVID-ME's synthesized
  schema. Missing actions are merged in automatically so policies
  referring to actions not declared in the schema still load.
- `ParsedPolicy.resourceEqualities` on the fallback parser: a list of
  `{ type?, id }` entries extracted from `resource == Type::"id"` or
  bare `resource == "id"` clauses. Matched by `policyMatchesRequest`.
- Bare-namespace rewriting in the WASM engine. Policies using bare
  `Type::"id"` references (e.g. `action == Action::"exec_command"`)
  are rewritten to carry the detected schema namespace before being
  submitted to Cedarling. Without this, Cedar resolves bare refs to
  the empty namespace and nothing matches.

### Changed
- `resource ==` constraints are no longer rejected as unsupported by
  the fallback parser. `resource == Namespace::Type::"id"` is parsed
  into `ParsedPolicy.resourceEqualities = [{ type: 'Namespace::Type',
  id: 'id' }]`. Matching is type-aware when the request names a
  resourceType, id-only otherwise.
- `evaluateWithWasm` omits the `path` attribute on the resource
  payload when `request.resourceType` is present. The synthesized
  `Resource` type declared `path`, but deployment-specific types like
  `Jans::Shell` don't — including the attribute caused Cedarling to
  silently drop policies at evaluation.

### Fixed
- `Carapace -> OVID-ME` pipeline now actually works. Verified with the
  real policy files from `~/.openclaw/mcp-policies/` + the real
  `schema.json`: `forbid(..., resource == Shell::"rm")` fires and
  denies, `Shell::"git"` allows through the wildcard permit.

### Tests
- 16 new tests in `test/carapace-integration.test.ts` covering:
  - multi-statement fallback parsing
  - typed resource-equality matching (including type mismatches)
  - WASM end-to-end with bare-namespace rewriting
  - WASM with a realistic Jans schema containing Shell/Workload/Agent
  - external-schema action merging
- 193/193 total tests pass.

### Known gap
- Carapace's `call_tool`/`call_api` actions use a context object with
  typed attributes. OVID-ME's fallback engine ignores context
  conditions beyond `resource.path like`. If a Carapace policy relies
  on `when { context.agent_role == ... }` it currently evaluates
  through WASM only. Fallback path is fail-closed for context conditions.

## [0.3.1] - 2026-04-19

Follow-up patches after end-to-end testing against real Carapace `.cedar`
policy files uncovered two regressions in the 0.3.0 parser/WASM work.

### Fixed
- **Bare `Action::"X"` now parses.** Real Carapace policies use the bare
  form (`forbid(principal, action == Action::"exec_command", resource);`)
  with no namespace prefix. The namespace-agnostic parser from 0.3.0
  required at least one `Namespace::Action::"X"` and rejected bare
  Action literals as malformed action clauses. Now accepts
  `(?:<Namespace>::)?Action::"X"` and records `''` on
  `actionNamespaces` when no prefix is present.
- **WASM handles multi-statement policy blobs.** Cedarling's
  `policy_content` decoder expects one Cedar statement per policy
  entry. `CarapacePolicySource.getEffectivePolicy()` returns the
  concatenation of all `.cedar` files, which is virtually always
  multi-statement. WASM was returning `null` on every real deployment.
  `buildPolicyStore()` now splits on top-level `permit(`/`forbid(`
  boundaries and submits each as a separate policy entry.
- **Stale hardcoded version in authzen test.** The test asserted
  `body.version === '0.2.0'`; now imports `OVID_ME_VERSION` from
  `src/version.ts` so future releases don't trip it.

### Known limitation
Carapace's Cedar vocabulary uses custom entity types like `Shell` that
do not match OVID-ME's synthesized `<namespace>::Resource` schema.
Full Carapace-policy evaluation through WASM still needs a
schema-compat layer; tracked as a separate piece of work. The fallback
parser explicitly rejects `resource == <Type>::".."` clauses today.

## [0.3.0] - 2026-04-19

Security-hardening release. Closes findings #3, #4, #6, #8, #9, #10,
and #11 from the verified code review.

### Breaking Changes
- `MandateEngine.verifySubset` no longer silently accepts a child policy
  whose text happens to appear inside the parent. The unsound
  `String.includes` fallback is removed. Default behavior when the SMT
  prover is unavailable is now **fail closed**. Opt-in reflexive
  fallbacks are available via `OvidConfig.structuralFallback:
  'off' | 'exact' | 'normalized'` (default `'off'`).
- `AuthZenServer` and `DashboardServer` now bind to `127.0.0.1` by
  default (was: all interfaces) and require a bearer token. Existing
  deployments that relied on anonymous access will see `401` after
  upgrade. Migration:
  - Local dev: `OVID_ME_ALLOW_LOOPBACK_NO_AUTH=1`.
  - Persistent token: `OVID_ME_AUTH_TOKEN=<token>`.
  - Programmatic: `{ security: { auth: { disabled: true } } }` (loopback
    only).
- `POST /api/import` on the dashboard has been **removed**. It was an
  arbitrary-file-read primitive. Callers that need to import JSONL
  logs should use `AuditDatabase.importJsonl()` programmatically.
- `Access-Control-Allow-Origin: *` is no longer emitted by default.
  Wildcard CORS is rejected on non-loopback binds.
- `@janssenproject/cedarling_wasm` pinned to `^1.15.0` (was `^2.0.0`)
  to align with Carapace and to restore a working WASM evaluation
  path. The 2.0 schema JSON format had broken all WASM evaluation.

### Added
- `src/subset-structural.ts` with `exactMatch()`, `normalize()`, and
  `normalizedMatch()`. Reflexive-only; not general subset proofs.
- `VerifySubsetResult.method: 'smt' | 'structural-exact' |
  'structural-normalized' | 'none'` — auditors can distinguish
  cryptographic proofs from reflexive matches.
- `src/server-security.ts`: shared `SecurityConfig` type,
  `resolveSecurity()`, `applyCors()`, `verifyAuth()`,
  `announceAuthToken()` helpers for bind host + bearer token + CORS.
  Exported from the package index for downstream HTTP surfaces.
- Bearer-token auth via `Authorization: Bearer <token>` header or
  `?token=<t>` query string. Auto-generated tokens printed once to
  stderr at startup; preset via `OVID_ME_AUTH_TOKEN` or
  `SecurityConfig.auth.token`.
- Namespace-agnostic parser: `evaluate.ts` now parses any
  `<Namespace>::Action::"X"` form. Records namespaces seen on
  `ParsedPolicy`.
- Namespace-agnostic WASM engine: schema root, entity types, and
  workload mapping derive from the policy's declared namespace
  (previously hardcoded to `Ovid`).
- `src/version.ts` exports `OVID_ME_VERSION` (read from `package.json`
  at load time). AuthZEN PDP discovery at `GET /` now returns this
  dynamic value.
- `OVID_WASM_DEBUG=1` surfaces WASM evaluation errors instead of
  silently falling back.

### Fixed
- Finding #3: `parent.includes(child)` subset "proof" fallback could
  accept any child whose text appeared in a parent comment or between
  unrelated clauses. Regression test in
  `test/subset-structural.test.ts`.
- Finding #6: `Jans::`-namespaced action clauses previously left
  `actions = null`, which `policyMatchesRequest` treated as "wildcard
  matches every action," turning a narrow permit into an allow-all.
  Regression tests in `test/namespace.test.ts`.
- Finding #9: Carapace policies (`Jans::`) can now be evaluated by
  OVID-ME's fallback parser AND WASM engine. End-to-end tested.
- Finding #11: WASM evaluation path (Cedarling) returned `null` on
  every input due to 2.0 schema format drift. Resolved by pinning to
  `^1.15.0`. Both `Ovid::` and `Jans::` policies now evaluate end-to-
  end through WASM.
- Malformed action clauses (e.g. `action == "just_a_string"`) are now
  explicit parse errors rather than silent wildcards.

### Tests
- 177/177 pass (was 139). 38 new tests covering namespace parsing,
  subset-proof soundness, server security, and WASM end-to-end.

## [0.1.0] - 2026-03-23

### Added
- Cedar mandate evaluator with string-matching fallback engine
- MandateEngine with enforce/dry-run/shadow modes
- Subset proof stub (structural comparison, SMT future work)
- OvidConfig with deployment profiles (dev/startup/enterprise)
- PolicySource interface for deployment-level policy integration
- Audit logging (JSONL + SQLite)
- Forensics dashboard with timeline, delegation tree, Sankey flow
- Mandate breakdown views (activity, timeline, per-mandate actions)
- resolveConfig() with environment variable overrides

Split from @clawdreyhepburn/ovid — authorization logic now lives here.
