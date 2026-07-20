# Cedar Feature Support

OVID-ME includes two Cedar evaluation engines:

## Native cedar-wasm (default, recommended)

Full Cedar evaluation via official `@cedar-policy/cedar-wasm` (`isAuthorized`).
Same engine family as Carapace 1.0.12+. Supports Cedar features including:

- Entity hierarchies (`in` operator)
- `unless` clauses
- Boolean combinators (`&&`, `||`)
- `has` operator
- `.contains()`, `.containsAll()`, `.containsAny()`
- IP and decimal extensions
- Full `when`/`unless` context conditions (including `context.path like "..."`)

This is the **default** (`engine: "wasm"`). If the native engine cannot load or
evaluate a request, OVID-ME **fail-closes** (deny) — it does **not** silently
degrade to the string matcher.

`engine: "auto"` tries WASM first and also fail-closes on failure. It is not a
path back to the matcher.

## Fallback String Matcher (explicit opt-in only)

Used only when you set `engine: "fallback"`. Supports a **subset** of Cedar:

### Supported

- `permit(principal, action == Ovid::Action::"x", resource)`
- `permit(principal, action in [Ovid::Action::"x", ...], resource)`
- `permit(principal, action, resource)` (wildcard)
- `when { resource.path like "/pattern/*" }` (single glob condition)
- `forbid(...)` with same patterns
- Default-deny semantics
- Forbid overrides permit

### NOT supported (will be rejected with an error)

- `unless` clauses
- `principal == ...` or `resource == ...` in head (partial)
- Boolean combinators in `when` (`&&`, `||`)
- `has` operator
- `.contains()`, `.containsAll()`, `.containsAny()`
- IP/decimal extensions
- Entity hierarchy (`in` on non-action types)
- Context conditions other than simple path globs the matcher understands

### Behavior on unsupported syntax

By default (strict mode), the fallback engine **rejects** policies with unsupported syntax rather than silently mis-evaluating them. Prefer native `engine: "wasm"` for full Cedar.

## Cedar Schema

The bundled `schema/Ovid.cedarschema` includes common agent actions. The native
WASM path also synthesizes/augments schema from policy text and optional
external schemas (e.g. Carapace `schema.json` under the `Jans` namespace), so
custom actions referenced by a mandate still load.
