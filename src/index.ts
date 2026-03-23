// Re-export CedarMandate for convenience
export type { CedarMandate } from '@clawdreyhepburn/ovid';

export { AuditLogger, createAuditLogger, defaultAuditLogger } from './audit.js';
export type { DecisionOutcome, AuditEntry } from './audit.js';
export { generateSankeyHtml } from './visualize.js';
export { AuditDatabase } from './audit-db.js';
export { DashboardServer, startDashboard, stopDashboard } from './dashboard-server.js';
export { dashboardHtml } from './dashboard-html.js';
export type { OvidConfig, PolicySource } from './config.js';
export { DEFAULT_CONFIG, resolveConfig } from './config.js';
export type { EvaluateRequest, EvaluateResult, EngineMode } from './evaluate.js';
export { evaluateMandate, evaluateMandateAsync } from './evaluate.js';
export { evaluateWithWasm, isWasmAvailable } from './cedar-engine-wasm.js';
export { proveSubset, proverBinaryExists } from './subset-prover.js';
export type { SubsetProofResult } from './subset-prover.js';
export { MandateEngine } from './mandate-engine.js';
