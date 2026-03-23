import { describe, it, expect } from 'vitest'
import { evaluateMandate, parsePolicies } from '../src/evaluate.js'
import type { EvaluateRequest } from '../src/evaluate.js'
import type { CedarMandate } from '../src/config.js'

function mkMandate(...policies: string[]): CedarMandate {
  return { rarFormat: 'cedar', cedar_policies: policies }
}

describe('evaluateMandate', () => {
  it('permits exact action match', async () => {
    const mandate = mkMandate('permit(principal, action == Ovid::Action::"read_file", resource);')
    const result = await evaluateMandate(mandate, { action: 'read_file', resource: '/foo' })
    expect(result.decision).toBe('allow')
  })

  it('denies non-matching action', async () => {
    const mandate = mkMandate('permit(principal, action == Ovid::Action::"read_file", resource);')
    const result = await evaluateMandate(mandate, { action: 'exec', resource: '/foo' })
    expect(result.decision).toBe('deny')
  })

  it('permits action list match', async () => {
    const mandate = mkMandate(
      'permit(principal, action in [Ovid::Action::"read_file", Ovid::Action::"write_file"], resource);'
    )
    const r1 = await evaluateMandate(mandate, { action: 'read_file', resource: '/x' })
    const r2 = await evaluateMandate(mandate, { action: 'write_file', resource: '/x' })
    const r3 = await evaluateMandate(mandate, { action: 'exec', resource: '/x' })
    expect(r1.decision).toBe('allow')
    expect(r2.decision).toBe('allow')
    expect(r3.decision).toBe('deny')
  })

  it('permits resource glob match', async () => {
    const mandate = mkMandate(
      'permit(principal, action, resource) when { resource.path like "/src/*" };'
    )
    const r1 = await evaluateMandate(mandate, { action: 'read_file', resource: '/src/index.ts' })
    const r2 = await evaluateMandate(mandate, { action: 'read_file', resource: '/etc/passwd' })
    expect(r1.decision).toBe('allow')
    expect(r2.decision).toBe('deny')
  })

  it('default deny with no policies', async () => {
    const mandate = mkMandate()
    const result = await evaluateMandate(mandate, { action: 'read_file', resource: '/foo' })
    expect(result.decision).toBe('deny')
    expect(result.reason).toContain('default deny')
  })

  it('forbid overrides permit', async () => {
    const mandate = mkMandate(
      'permit(principal, action == Ovid::Action::"exec", resource);',
      'forbid(principal, action == Ovid::Action::"exec", resource);'
    )
    const result = await evaluateMandate(mandate, { action: 'exec', resource: 'rm -rf' })
    expect(result.decision).toBe('deny')
    expect(result.reason).toContain('forbid')
  })

  it('forbid all denies everything', async () => {
    const mandate = mkMandate(
      'permit(principal, action == Ovid::Action::"read_file", resource);',
      'forbid(principal, action, resource);'
    )
    const result = await evaluateMandate(mandate, { action: 'read_file', resource: '/foo' })
    expect(result.decision).toBe('deny')
  })

  it('multiple policies — permit matched', async () => {
    const mandate = mkMandate(
      'permit(principal, action == Ovid::Action::"read_file", resource);',
      'permit(principal, action == Ovid::Action::"write_file", resource);'
    )
    const result = await evaluateMandate(mandate, { action: 'write_file', resource: '/foo' })
    expect(result.decision).toBe('allow')
  })

  it('dry-run mode always allows but preserves info', async () => {
    const mandate = mkMandate('permit(principal, action == Ovid::Action::"read_file", resource);')
    const result = await evaluateMandate(mandate, { action: 'exec', resource: '/x' }, { mandateMode: 'dry-run' })
    expect(result.decision).toBe('allow')
    expect(result.mode).toBe('dry-run')
  })
})

describe('parsePolicies', () => {
  it('handles empty string', () => {
    expect(parsePolicies('')).toHaveLength(0)
  })

  it('parses forbid with specific action', () => {
    const policies = parsePolicies('forbid(principal, action == Ovid::Action::"exec", resource);')
    expect(policies).toHaveLength(1)
    expect(policies[0].effect).toBe('forbid')
    expect(policies[0].actions).toEqual(['exec'])
  })
})
