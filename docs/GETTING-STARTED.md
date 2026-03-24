# Getting Started with OVID-ME

OVID-ME evaluates Cedar policy mandates carried in OVID tokens. This guide walks you through setup, first use, and going to production.

## 1. Install both plugins

OVID-ME depends on OVID for token creation and verification:

```bash
openclaw plugins install @clawdreyhepburn/openclaw-ovid
openclaw plugins install @clawdreyhepburn/openclaw-ovid-me
```

## 2. Restart the gateway

```bash
openclaw gateway restart
```

## 3. Enable the tools

Add to your `openclaw.json`:

```json
{
  "agents": {
    "list": [{
      "id": "main",
      "tools": {
        "allow": ["openclaw-ovid", "openclaw-ovid-me"]
      }
    }]
  }
}
```

## 4. Mint your first token

Ask your agent to:

```
Use ovid_mint with mandate:
  permit(principal, action == Ovid::Action::"read_file", resource);
  forbid(principal, action, resource);
```

This creates an OVID token where the agent can read files but nothing else.

## 5. Evaluate a tool call

Ask your agent to:

```
Use ovid_evaluate with that mandate to check if action "read_file" on resource "/src/index.ts" is allowed
```

Expected result: **allow** (matches the permit policy).

Try again with action `"exec"` — expected result: **deny** (caught by the forbid-all).

## 6. Check the dashboard

Configure audit storage in your plugin config:

```json
{
  "auditLog": "~/.ovid/audit.jsonl",
  "auditDb": "~/.ovid/audit.db",
  "dashboardPort": 19831
}
```

Then visit `http://localhost:19831` for the forensics dashboard with timeline, delegation tree, and action breakdown.

## 7. Go from dry-run to enforce

OVID-ME defaults to **enforce** mode. For testing, start with dry-run:

- `"mandateMode": "dry-run"` — evaluates and logs, but always allows
- `"mandateMode": "shadow"` — enforces current mandate + evaluates a candidate in parallel
- `"mandateMode": "enforce"` — deny means deny (production)

Recommended path: dry-run → shadow → enforce.

## 8. What happens when tokens expire?

Default TTL is 30 minutes. For long-running tasks, set a longer TTL:

```typescript
const agent = await createOvid({
  // ...
  ttlSeconds: 3600, // 1 hour
});
```

For critical workflows, use `renewOvid()` programmatically before expiry.

---

## Troubleshooting

### "All my tool calls are denied"

1. Check `mandateMode` — start with `"dry-run"` to see what would happen without enforcement
2. Verify your mandate covers the actions your agent uses (e.g., `read_file`, `write_file`, `exec`, `web_fetch`, `message`)
3. Remember: Cedar is default-deny. If no permit policy matches, the action is denied

### "WASM engine not found"

Install the optional WASM dependency:

```bash
npm install @janssenproject/cedarling_wasm
```

Without it, OVID-ME uses the fallback string-matching engine, which supports a subset of Cedar. See [CEDAR-SUPPORT.md](CEDAR-SUPPORT.md) for limitations.

### "Unmet peer dependency"

Both packages are required:

```bash
npm install @clawdreyhepburn/ovid @clawdreyhepburn/ovid-me
```

### "Unsupported Cedar syntax" errors

The fallback engine rejects policies with features it can't evaluate (e.g., `unless`, `has`, `.contains()`). Either:

- Install @janssenproject/cedarling_wasm for full Cedar support
- Simplify your mandate to use only supported patterns (see [CEDAR-SUPPORT.md](CEDAR-SUPPORT.md))
