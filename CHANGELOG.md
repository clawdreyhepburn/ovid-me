# Changelog

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
