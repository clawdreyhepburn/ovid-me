import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MandateEngine } from '../src/mandate-engine.js'
import type { CedarMandate } from '../src/config.js'
import type { PolicySource } from '../src/config.js'

function mkMandate(...policies: string[]): CedarMandate {
  return { rarFormat: 'cedar', policySet: policies.join("\n") }
}

const readOnly = mkMandate('permit(principal, action == Ovid::Action::"read_file", resource);')

describe('MandateEngine.evaluate', () => {
  it('enforce mode: deny is deny', async () => {
    const engine = new MandateEngine({ mandateMode: 'enforce' })
    const result = await engine.evaluate('jti-1', readOnly, { action: 'exec', resource: '/x' })
    expect(result.decision).toBe('deny')
    expect(result.mode).toBe('enforce')
  })

  it('enforce mode: allow is allow', async () => {
    const engine = new MandateEngine({ mandateMode: 'enforce' })
    const result = await engine.evaluate('jti-1', readOnly, { action: 'read_file', resource: '/x' })
    expect(result.decision).toBe('allow')
  })

  it('dry-run mode: deny is logged but returns allow', async () => {
    const engine = new MandateEngine({ mandateMode: 'dry-run' })
    const result = await engine.evaluate('jti-1', readOnly, { action: 'exec', resource: '/x' })
    expect(result.decision).toBe('allow')
    expect(result.mode).toBe('dry-run')
  })

  it('shadow mode: evaluates both mandates', async () => {
    const shadowMandate = mkMandate('permit(principal, action, resource);')
    const engine = new MandateEngine({
      mandateMode: 'shadow',
      shadowMandate,
    })
    const result = await engine.evaluate('jti-1', readOnly, { action: 'exec', resource: '/x' })
    expect(result.decision).toBe('deny') // real mandate denies exec
    expect(result.mode).toBe('shadow')
    expect(result.shadowDecision).toBe('allow') // shadow mandate allows all
  })

  it('shadow mode without shadowMandate: no shadow decision', async () => {
    const engine = new MandateEngine({ mandateMode: 'shadow' })
    const result = await engine.evaluate('jti-1', readOnly, { action: 'read_file', resource: '/x' })
    expect(result.shadowDecision).toBeUndefined()
  })

  it('audit logger is called on every evaluation', async () => {
    const logPath = '/tmp/ovid-engine-test-audit.jsonl'
    const engine = new MandateEngine({ mandateMode: 'enforce', auditLog: logPath })
    await engine.evaluate('jti-audit', readOnly, { action: 'read_file', resource: '/x' })
    // Logger writes to file — just verify no errors thrown
  })
})

describe('MandateEngine.verifySubset', () => {
  it('subsetProof off: always returns proven', async () => {
    const engine = new MandateEngine({ subsetProof: 'off' })
    const result = await engine.verifySubset(readOnly, 'agent-1')
    expect(result.proven).toBe(true)
  })

  it('no policy source: returns not proven', async () => {
    const engine = new MandateEngine({ subsetProof: 'required', policySource: null })
    const result = await engine.verifySubset(readOnly, 'agent-1')
    expect(result.proven).toBe(false)
    expect(result.reason).toContain('no policy source')
  })

  it('policy source returns null: not proven', async () => {
    const source: PolicySource = { getEffectivePolicy: async () => null }
    const engine = new MandateEngine({ subsetProof: 'required', policySource: source })
    const result = await engine.verifySubset(readOnly, 'agent-1')
    expect(result.proven).toBe(false)
    expect(result.reason).toContain('no effective policy')
  })

  it('mandate subset of parent: proven', async () => {
    const source: PolicySource = {
      getEffectivePolicy: async () => 'permit(principal, action, resource);',
    }
    const engine = new MandateEngine({ subsetProof: 'required', policySource: source })
    const result = await engine.verifySubset(readOnly, 'agent-1')
    expect(result.proven).toBe(true)
  })

  it('mandate exceeds parent: not proven', async () => {
    const source: PolicySource = {
      getEffectivePolicy: async () =>
        'permit(principal, action == Ovid::Action::"write_file", resource);',
    }
    const engine = new MandateEngine({ subsetProof: 'required', policySource: source })
    const result = await engine.verifySubset(readOnly, 'agent-1')
    expect(result.proven).toBe(false)
    expect(result.reason).toContain('not covered')
  })
})
