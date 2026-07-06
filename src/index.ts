// Re-export types for convenience
export type { AuthorizationDetail, CedarMandate } from '@clawdreyhepburn/ovid';
export { OVID_ME_VERSION } from './version.js';

export { AuditLogger, createAuditLogger, defaultAuditLogger } from './audit.js';
export type { DecisionOutcome, AuditEntry } from './audit.js';
export { generateSankeyHtml } from './visualize.js';
export { AuditDatabase } from './audit-db.js';
export { DashboardServer, startDashboard, stopDashboard } from './dashboard-server.js';
export { dashboardHtml } from './dashboard-html.js';
export type { OvidConfig, PolicySource } from './config.js';
export { DEFAULT_CONFIG, resolveConfig } from './config.js';
export type { EvaluateRequest, EvaluateResult, EngineMode, EvaluateAsyncOptions } from './evaluate.js';
export { evaluateMandate, evaluateMandateAsync } from './evaluate.js';
export { evaluateWithWasm, isWasmAvailable } from './cedar-engine-wasm.js';
export type { EvaluateWithWasmOptions } from './cedar-engine-wasm.js';
export { proveSubset, proverBinaryExists } from './subset-prover.js';
export type { SubsetProofResult } from './subset-prover.js';
export { probePartial, probeOptions, partialProverExists, parsePartialOutput } from './partial-prover.js';
export type { PartialVerdict, PartialProbeResult, OptionQuery, OptionResult } from './partial-prover.js';
export { exactMatch, normalize, normalizedMatch } from './subset-structural.js';
export { MandateEngine } from './mandate-engine.js';
export type { AuthZenSubject, AuthZenAction, AuthZenResource, AuthZenRequest, AuthZenResponse, AuthZenBatchRequest, AuthZenBatchResponse, AuthZenBatchOptions } from './authzen.js';
export { authzenToEvaluateRequest, evaluateResultToAuthzen, validateAuthZenRequest } from './authzen.js';
export { AuthZenServer } from './authzen-server.js';
export type { AuthZenServerConfig } from './authzen-server.js';
export { resolveSecurity, applyCors, verifyAuth, announceAuthToken } from './server-security.js';
export type { SecurityConfig, AuthConfig, ResolvedSecurity } from './server-security.js';
