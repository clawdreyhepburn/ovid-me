import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { OvidClaims, OvidResult } from '@clawdreyhepburn/ovid';

export type DecisionOutcome = 'deny' | 'allow' | 'allow-proven' | 'allow-unproven';

export interface AuditEntry {
  ts: string;
  event: string;
  [key: string]: unknown;
}

export class AuditLogger {
  private filePath: string;
  private enabled: boolean;

  constructor(filePath?: string) {
    this.filePath = filePath ?? process.env.OVID_AUDIT_LOG ?? '';
    this.enabled = this.filePath.length > 0;
  }

  private write(entry: AuditEntry): void {
    if (!this.enabled) return;
    try {
      mkdirSync(dirname(this.filePath), { recursive: true });
    } catch { /* exists */ }
    appendFileSync(this.filePath, JSON.stringify(entry) + '\n');
  }

  logIssuance(claims: OvidClaims): void {
    this.write({
      ts: new Date().toISOString(),
      event: 'issuance',
      jti: claims.jti,
      iss: claims.iss,
      sub: claims.sub,
      role: 'mandate',
      mandate: claims.mandate ? 'present' : 'absent',
      parent_chain: claims.parent_chain,
      exp: claims.exp,
    });
  }

  logVerification(jti: string, result: OvidResult, verifier?: string): void {
    this.write({
      ts: new Date().toISOString(),
      event: 'verification',
      jti,
      valid: result.valid,
      principal: result.principal,
      mandate: result.mandate ? 'present' : 'absent',
      chain: result.chain,
      expiresIn: result.expiresIn,
      ...(verifier ? { verifier } : {}),
    });
  }

  logDecision(
    agentJti: string,
    action: string,
    resource: string,
    decision: DecisionOutcome,
    policies?: string[],
  ): void {
    this.write({
      ts: new Date().toISOString(),
      event: 'decision',
      agentJti,
      action,
      resource,
      decision,
      ...(policies ? { policies } : {}),
    });
  }

  logCustom(event: string, data: Record<string, unknown>): void {
    this.write({
      ts: new Date().toISOString(),
      event,
      ...data,
    });
  }
}

/** Default singleton — only active if OVID_AUDIT_LOG env var is set */
export const defaultAuditLogger = new AuditLogger();

/** Factory to create a logger writing to a specific path */
export function createAuditLogger(path: string): AuditLogger {
  return new AuditLogger(path);
}
