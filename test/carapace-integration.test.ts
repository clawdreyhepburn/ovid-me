/**
 * End-to-end integration test for Carapace -> OVID-ME policy flow.
 *
 * This is the real-world scenario: Carapace writes .cedar policy files
 * using bare `Action::"X"` and `Type::"id"` syntax, and a declared
 * Jans-namespace schema.json. CarapacePolicySource reads those files
 * verbatim. OVID-ME must be able to:
 *
 *   1. Parse multi-statement policy blobs through the fallback engine.
 *   2. Evaluate bare-namespace references through the WASM engine by
 *      rewriting them to carry the deployment's schema namespace.
 *   3. Apply resource-equality constraints (`resource == Shell::"rm"`)
 *      in BOTH engines.
 *   4. Respect the deployment's custom entity types when specified on
 *      EvaluateRequest (resourceType / principalType).
 *
 * Before the Carapace-compat work (2026-04-19), none of this worked:
 *   - fallback parser rejected resource_equality clauses
 *   - WASM silently failed to match bare references
 *   - every real Carapace -> OVID-ME pipeline was broken at the
 *     vocabulary layer.
 */

import { describe, it, expect } from 'vitest';
import { evaluateMandate, evaluateMandateAsync, parsePolicies } from '../src/evaluate.js';
import { isWasmAvailable } from '../src/cedar-engine-wasm.js';

// Realistic Carapace policy text. Same shape as what lives at
// ~/.openclaw/mcp-policies/*.cedar on the dev host.
const ALLOW_ALL = `permit (
  principal,
  action,
  resource
);`;

const DENY_RM = `forbid (
  principal,
  action == Action::"exec_command",
  resource == Shell::"rm"
);`;

const COMBINED = ALLOW_ALL + '\n\n' + DENY_RM;

// Minimal Jans-namespace schema with the entity types and actions the
// policies above actually reference. Matches the structure of Carapace's
// schema.json.
const JANS_SCHEMA = {
  Jans: {
    entityTypes: {
      Workload: {
        shape: {
          type: 'Record',
          attributes: {
            name: { type: 'EntityOrCommon', name: 'String', required: false },
          },
        },
      },
      Shell: {
        shape: {
          type: 'Record',
          attributes: {
            command: { type: 'EntityOrCommon', name: 'String', required: false },
            workdir: { type: 'EntityOrCommon', name: 'String', required: false },
          },
        },
      },
      Agent: {
        shape: {
          type: 'Record',
          attributes: {
            role: { type: 'EntityOrCommon', name: 'String', required: false },
          },
        },
      },
    },
    actions: {
      exec_command: {
        appliesTo: {
          principalTypes: ['Workload', 'Agent'],
          resourceTypes: ['Shell'],
          context: { type: 'Record', attributes: {} },
        },
      },
    },
  },
};

describe('Carapace -> OVID-ME integration', () => {
  describe('fallback parser accepts Carapace vocabulary', () => {
    it('parses multi-statement permit + forbid blob', () => {
      const policies = parsePolicies(COMBINED);
      expect(policies).toHaveLength(2);
      expect(policies[0].effect).toBe('permit');
      expect(policies[1].effect).toBe('forbid');
    });

    it('parses `resource == Shell::"rm"` equality clause', () => {
      const policies = parsePolicies(DENY_RM);
      expect(policies).toHaveLength(1);
      expect(policies[0].resourceEqualities).toEqual([
        { type: 'Shell', id: 'rm' },
      ]);
    });

    it('does NOT reject resource_equality as unsupported (regression)', () => {
      // Before 2026-04-19 this threw UnsupportedCedarSyntaxError.
      expect(() => parsePolicies(DENY_RM)).not.toThrow();
    });

    it('fallback: forbid matches on Shell::"rm" and denies', () => {
      const result = evaluateMandate(COMBINED, {
        action: 'exec_command',
        resource: 'rm',
        resourceType: 'Shell',
      });
      expect(result.decision).toBe('deny');
    });

    it('fallback: permit allows git when no forbid matches', () => {
      const result = evaluateMandate(COMBINED, {
        action: 'exec_command',
        resource: 'git',
        resourceType: 'Shell',
      });
      expect(result.decision).toBe('allow');
    });

    it('fallback: typed equality only fires when types match', () => {
      // Same resource id but a different type should NOT trigger the
      // Shell::"rm" forbid. We still evaluate the permit so it allows.
      const result = evaluateMandate(COMBINED, {
        action: 'exec_command',
        resource: 'rm',
        resourceType: 'Tool', // <-- mismatched type
      });
      expect(result.decision).toBe('allow');
    });

    it('fallback: forbid without request.resourceType still fires by id', () => {
      // Deployments migrating piecemeal may not send resourceType on
      // every request. Fall back to id-only match.
      const result = evaluateMandate(COMBINED, {
        action: 'exec_command',
        resource: 'rm',
      });
      expect(result.decision).toBe('deny');
    });
  });

  describe('WASM engine accepts Carapace vocabulary', () => {
    it('evaluates bare Action::"X" correctly (namespace rewriting)', async () => {
      if (!(await isWasmAvailable())) return;
      const policy = 'permit(principal, action == Action::"exec_command", resource);';
      const result = await evaluateMandateAsync(policy, 'agent-1', {
        action: 'exec_command',
        resource: '/bin/ls',
      }, 'wasm');
      expect(result.engine).toBe('wasm');
      expect(result.decision).toBe('allow');
    });

    it('forbid on Shell::"rm" denies under external Jans schema', async () => {
      if (!(await isWasmAvailable())) return;
      const result = await evaluateMandateAsync(COMBINED, 'agent-1', {
        action: 'exec_command',
        resource: 'rm',
        resourceType: 'Shell',
        principalType: 'Workload',
      }, 'wasm', { externalSchema: JANS_SCHEMA });
      expect(result.engine).toBe('wasm');
      expect(result.decision).toBe('deny');
    });

    it('permit allows git (no matching forbid) under external Jans schema', async () => {
      if (!(await isWasmAvailable())) return;
      const result = await evaluateMandateAsync(COMBINED, 'agent-1', {
        action: 'exec_command',
        resource: 'git',
        resourceType: 'Shell',
        principalType: 'Workload',
      }, 'wasm', { externalSchema: JANS_SCHEMA });
      expect(result.engine).toBe('wasm');
      expect(result.decision).toBe('allow');
    });

    it('external schema action names merge with policy actions', async () => {
      // Policy references an action (read_file) that the external schema
      // doesn't declare. We want Cedarling to still load the policy
      // rather than reject it for referencing an unknown action.
      if (!(await isWasmAvailable())) return;
      const policy = 'permit(principal, action == Action::"read_file", resource);';
      const result = await evaluateMandateAsync(policy, 'agent-1', {
        action: 'read_file',
        resource: '/etc/hosts',
        resourceType: 'Shell',
        principalType: 'Workload',
      }, 'wasm', { externalSchema: JANS_SCHEMA });
      expect(result.engine).toBe('wasm');
      expect(result.decision).toBe('allow');
    });
  });
});
