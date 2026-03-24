# Cedar Feature Support

OVID-ME includes two Cedar evaluation engines:

## Cedarling WASM (recommended)

Full Cedar 4.x evaluation via @janssenproject/cedarling_wasm.
Supports all Cedar features including:

- Entity hierarchies (`in` operator)
- `unless` clauses
- Boolean combinators (`&&`, `||`)
- `has` operator
- `.contains()`, `.containsAll()`, `.containsAny()`
- IP and decimal extensions
- Full `when`/`unless` context conditions

Automatically used when @janssenproject/cedarling_wasm is installed.

## Fallback String Matcher

Used when WASM is unavailable. Supports a **subset** of Cedar:

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
- `principal == ...` or `resource == ...` in head
- Boolean combinators in `when` (`&&`, `||`)
- `has` operator
- `.contains()`, `.containsAll()`, `.containsAny()`
- IP/decimal extensions
- Entity hierarchy (`in` on non-action types)
- Context conditions other than `resource.path like "..."`

### Behavior on unsupported syntax

By default (strict mode), the fallback engine **rejects** policies with unsupported syntax rather than silently mis-evaluating them. This means:

- If your mandate uses unsupported features, install @janssenproject/cedarling_wasm
- Or simplify your mandate to use only supported patterns

To check which engine is active, use the `ovid-me status` CLI command.

## Cedar Schema

Cedar requires all actions to be declared in the schema. The bundled `schema/Ovid.cedarschema` includes common agent actions (`read_file`, `write_file`, `exec`, `use_tool`, `web_fetch`, `message`, `spawn_agent`, `mcp_call`).

If your mandate uses custom actions not listed in the schema, add them:

```cedarschema
// In schema/Ovid.cedarschema, add inside namespace Ovid { ... }:
action "my_custom_action" appliesTo {
  principal: [Agent],
  resource: [Resource],
  context: {},
};
```

The WASM engine dynamically extracts actions from policy text, so it will work even without schema changes. The schema is primarily for Cedar CLI validation and documentation.
