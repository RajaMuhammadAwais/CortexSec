# CortexSec Development Roadmap: Production Orchestrator v1.0

## Why this roadmap exists
This roadmap translates the Production Orchestrator v1.0 goals into implementation-ready workstreams.
Each task is written in "human logic" order: **think first, constrain risk, design data flow, then write code**.

---

## Operating rule for every task (before coding)
Use this checklist before implementing any item below:

1. **Clarify objective**: What user/business risk does this task reduce?
2. **Define safety boundary**: What must never happen (destructive testing, out-of-scope targets, data leakage)?
3. **Define inputs/outputs**: What data enters this component, and what artifact should it emit?
4. **Decide verification method**: Which unit/integration tests prove the feature works?
5. **Decide rollback strategy**: If behavior regresses, how can we quickly disable/revert it?
6. **Only then write code** in small slices with tests.

---

## Phase 1 — Core Safety and Scope Validation Enhancement
**Objective:** Enforce zero-risk operations and strict authorized-target validation.

### 1.1 Implement scope file parser and validator
**Human logic steps**
1. Define one canonical scope schema (targets, exclusions, legal approval metadata, timeframe).
2. Decide accepted formats (JSON/YAML) and strict required fields.
3. Determine failure policy (hard fail + escalation if missing/invalid).
4. Implement parser and typed model validation.
5. Add signature/hash integrity verification when metadata includes signed proof.
6. Wire validation into CLI startup path before any agent/tool executes.
7. Add tests for happy path and all malformed-scope branches.

**Implementation TODO**
- Create typed scope contracts in `cortexsec/api/contracts`.
- Add `load_scope_file()` utility in `cortexsec/utils/scope_utils.py`.
- Add optional cryptographic verification helper (SHA256 + signer metadata support).
- Add `--scope-file` to CLI start command.
- Halt execution with escalation message and non-zero exit code when validation fails.
- Store validated scope object in `PentestContext`.

### 1.2 Enhance non-destructive testing enforcement
**Human logic steps**
1. Enumerate all currently invokable actions and classify them: safe vs potentially invasive.
2. Define a global `safe_mode` policy table that rewrites/blocks risky actions.
3. Add centralized enforcement so individual agents cannot bypass policy.
4. Create payload generation rules restricted to detection-only probes.
5. Add automatic cleanup contracts for generated payload artifacts.
6. Test policy bypass attempts and ensure denial is deterministic.

**Implementation TODO**
- Add a global `safe_mode` flag in runtime config.
- Add command guardrails in all tool adapters.
- Implement a `PayloadDesigner` agent with detection-only payload templates.
- Add policy-audit logs for blocked actions.

### 1.3 Develop sandbox integration for tool execution
**Human logic steps**
1. Define threat model for tool execution (network abuse, host mutation, resource exhaustion).
2. Specify mandatory isolation controls (CPU/memory/pid limits, filesystem restrictions).
3. Define default network policy (allowlist only, block lateral movement).
4. Apply least privilege to containerized tool runtime.
5. Verify sandbox escape resistance with controlled tests.

**Implementation TODO**
- Harden `DockerSandboxRunner` with explicit resource limits.
- Add network policy and egress controls.
- Add execution-time guardrails and timeout handling.
- Add tests validating sandbox policy behavior.

---

## Phase 2 — Advanced Tool Integration
**Objective:** Expand real-world scanner coverage while preserving safety guarantees.

### 2.1 Integrate sqlmap (safe mode)
**Human logic steps**
1. Define allowed sqlmap flags that remain non-destructive.
2. Build command composer that rejects unsafe switches.
3. Parse output into normalized findings model.
4. Add provenance metadata (tool, command profile, timestamp).
5. Validate with fixture outputs.

**Implementation TODO**
- Add `SqlmapAdapter` with safe-default command profile.
- Add structured parser for sqlmap output.
- Register `SqlmapPlugin` in builtins.

### 2.2 Integrate ffuf
**Human logic steps**
1. Determine safe wordlist strategy and request throttling limits.
2. Define endpoint-interest scoring logic.
3. Parse ffuf JSON output to normalized findings.
4. Correlate discovered paths with existing recon graph.

**Implementation TODO**
- Add `FfufAdapter` and parser.
- Register `FfufPlugin`.
- Add timeout/rate-limit safe defaults.

### 2.3 Integrate Burp Suite export ingestion
**Human logic steps**
1. Define supported export formats and schema versions.
2. Build parser with strict validation and deduplication.
3. Preserve evidence references from Burp artifacts.
4. Merge imported findings into CortexSec context graph.

**Implementation TODO**
- Create Burp XML/JSON importer module.
- Add processing pipeline to convert imports into findings.
- Add context merge logic with dedupe keys.

### 2.4 Enhance ScannerIntegrator agent
**Human logic steps**
1. Define decision policy for tool choice based on target type and phase.
2. Add confidence-driven fallback when one tool lacks context.
3. Track execution cost vs evidence gain.
4. Add explainability logs for tool-selection decisions.

**Implementation TODO**
- Upgrade `ScannerIntegrator` orchestration logic.
- Add contextual tool-selection heuristics.
- Add reasoned fallback behavior.

---

## Phase 3 — Compliance Mapping
**Objective:** Map every finding to required standards and enterprise controls.

### 3.1 OWASP Top 10 mapping
**Human logic steps**
1. Build mapping dictionary from finding attributes to OWASP categories.
2. Add confidence score for mapping quality.
3. Ensure mapping appears in analysis + reports.

### 3.2 CVSS v3.1 scoring
**Human logic steps**
1. Define required fields for base metrics.
2. Implement deterministic vector builder.
3. Verify scores against known CVSS examples.

### 3.3 MITRE ATT&CK mapping
**Human logic steps**
1. Define technique inference rules from observed behavior/evidence.
2. Add ATT&CK IDs and rationale text to findings.

### 3.4 CWE mapping
**Human logic steps**
1. Add CWE taxonomy lookup by vulnerability pattern.
2. Include CWE IDs in final finding schema.

### 3.5 Enterprise ComplianceAgent
**Human logic steps**
1. Define control crosswalk data model (PCI-DSS, NIST 800-53, ISO 27001, GDPR).
2. Map each finding to one or more control statements.
3. Flag legal/regulatory implications.
4. Expose machine-readable compliance output for reporting.

---

## Phase 4 — Evidence Validation and Causal Reasoning Loops
**Objective:** Reduce false positives with evidence-backed, multi-agent evidence-based validation.

### 4.1 Enhance ReasoningAgent for causal analysis
**Human logic steps**
1. Model attack graph nodes/edges and evidence linkage.
2. Require explicit cause-effect rationale for escalation.
3. Track uncertainty at each link.

### 4.2 Develop evidence methodology loop
**Human logic steps**
1. Represent hypothesis as structured object.
2. Design controlled safe test plan.
3. Execute and collect observations.
4. Require independent verification from at least two agents.
5. Conclude with confidence + reproducibility trace.

### 4.3 Refine evidence collection and confidence scoring
**Human logic steps**
1. Normalize evidence schema (tool output ref, timestamp, artifact path, reproduction steps).
2. Update all agents to emit schema-compliant evidence.
3. Compute confidence from source quality, repeatability, and consensus.

### 4.4 Implement false-positive elimination logic
**Human logic steps**
1. Add reviewer gate that enforces 2-agent confirmation minimum for critical issues.
2. Route unconfirmed findings to backlog, not final report.
3. Maintain audit trail explaining accept/reject decisions.

---

## Phase 5 — Enterprise Workflow and Reporting Upgrades
**Objective:** Deliver operational scale, integrations, and executive-grade output formats.

### 5.1 Batch target execution
**Human logic steps**
1. Define batch input schema and queue semantics.
2. Add per-target isolation and failure containment.
3. Aggregate batch summary metrics.

### 5.2 Scheduled assessments
**Human logic steps**
1. Define schedule model (one-off, cron-like, interval).
2. Validate timezone handling and missed-run behavior.
3. Ensure idempotent job re-execution.

### 5.3 API mode for CI/CD
**Human logic steps**
1. Define API contract first (stateful/stateless endpoints).
2. Add authn/authz and request validation.
3. Add asynchronous run status endpoints and webhooks.
4. Provide OpenAPI docs and usage examples.

### 5.4 Advanced outputs in ReportAgent
**Human logic steps**
1. Define one canonical report data model.
2. Render multiple outputs from same model (PDF, Markdown, STIX2, Jira payload).
3. Validate traceability: every report claim links to evidence.

### 5.5 Post-engagement learning
**Human logic steps**
1. Define storage schema for reusable patterns and remediation outcomes.
2. Add quality gate so only verified outcomes are learned.
3. Feed learned patterns back into planning/scoring logic.

---

## Phase 6 — Final Progress Report and Codebase Status
**Objective:** Close the release loop with measurable evidence of readiness.

### 6.1 Generate final report
**Human logic steps**
1. Compare implemented features against v1.0 requirements matrix.
2. Quantify gains (coverage, precision, runtime safety events).
3. List known gaps and explicit risks.

### 6.2 Update documentation
**Human logic steps**
1. Update README/user guides with new flags, workflows, and architecture.
2. Add migration notes for existing users.
3. Add operator playbook for incident-safe usage.

### 6.3 Code review and testing
**Human logic steps**
1. Enforce review checklist for safety/compliance/evidence integrity.
2. Run full unit + integration + regression suites.
3. Add release checklist and sign-off criteria.

---

## Execution cadence recommendation
- **Sprint structure:** 2-week sprints, one phase focus at a time.
- **Definition of Done:**
  - Feature implemented behind safe defaults.
  - Tests added (unit + integration where applicable).
  - Docs updated.
  - Evidence traceability validated.
- **Release gates:**
  - Safety gate (non-destructive + scope enforcement).
  - Evidence gate (reproducibility + timestamped artifacts).
  - Compliance gate (standards mapping coverage).

## Suggested first milestone (2 weeks)
1. Scope file validation in CLI with hard fail.
2. Global safe mode policy enforcement in adapters.
3. Sandbox resource/network restrictions with tests.
4. Preliminary compliance schema skeleton for OWASP + CVSS.
