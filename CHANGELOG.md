# Changelog

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
