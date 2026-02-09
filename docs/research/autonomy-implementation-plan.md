# CortexSec Autonomous Agent Implementation Plan (Research-Aligned)

This document converts research-backed recommendations into an execution plan for the CortexSec project.

## Objective

## Implementation Status

- ✅ Phase 1 kickoff started in codebase with:
  - planner/executor/critic I/O schemas,
  - safe command execution wrapper with provenance fields,
  - Thought/Action/Observation trace recording,
  - baseline policy checks for authorized mode and destructive mode block.
- ⏳ Remaining phase work is pending full integration into the primary supervisor workflow.

Build a practical autonomous security-assessment loop that is:
- evidence-driven,
- reproducible,
- policy-bounded,
- continuously measurable.

## Phase 1 — Core Autonomous Loop (Planner → Executor → Critic)

### Scope
Implement a three-role loop:
1. **Planner**: creates test hypotheses and action plans.
2. **Executor**: runs approved commands/tools and captures artifacts.
3. **Critic**: validates evidence quality, checks false-positive risk, and decides next action.

### Deliverables
- Agent role contract definitions (input/output schema).
- Iteration controller with max-steps, confidence delta, and safety stop conditions.
- Structured run record containing:
  - plan,
  - command/tool action,
  - output,
  - critic verdict,
  - updated confidence.

### Acceptance Criteria
- Every exploitability claim is linked to at least one execution artifact.
- Critic can reject weak evidence and request follow-up actions.
- Loop exits only when stopping criteria are met.

## Phase 2 — Tool Invocation Standardization (ReAct-style)

### Scope
Normalize all autonomous behavior into explicit traces:
- Thought
- Action
- Observation

### Deliverables
- Action templates for common tasks (recon, auth testing, injection checks).
- Safe command wrapper with timeout, exit code capture, and redaction hooks.
- Output parser interfaces for deterministic extraction.

### Acceptance Criteria
- No tool execution occurs without an explicit Action record.
- Every Observation includes timestamp + source command.

## Phase 3 — Memory and Learning (Reflexion-style)

### Scope
Introduce persistent memory for:
- failed hypotheses,
- false-positive signatures,
- previously successful validation paths.

### Deliverables
- Memory store schema (`hypothesis`, `result`, `error_pattern`, `reuse_score`).
- Retrieval strategy to bias planner toward high-yield actions.
- Decay/aging strategy for stale memories.

### Acceptance Criteria
- Repeated scans reduce duplicate dead-end actions.
- Planner cites memory entries when selecting next action.

## Phase 4 — Policy-as-Code Safety Layer

### Scope
Enforce guardrails pre-action and post-action.

### Mandatory Checks
- Authorized scope check.
- Non-destructive mode check.
- Endpoint sensitivity check.
- Rate/concurrency check.
- Data handling check (secrets/PII redaction).

### Deliverables
- Policy evaluation engine with allow/deny/explain result.
- Policy violation event log.

### Acceptance Criteria
- Disallowed actions are blocked with machine-readable reason.
- Reports include policy decisions for auditability.

## Phase 5 — Evidence Graph + Confidence Model

### Scope
Replace flat logs with graph-linked evidence.

### Data Model
`Target Surface -> Test Action -> Observation Artifact -> Hypothesis -> Confidence -> Finding`

### Deliverables
- Evidence graph serializer.
- Confidence update function (positive/negative evidence weighting).
- Finding requires minimum evidence score threshold.

### Acceptance Criteria
- Each finding can be traversed back to raw artifacts.
- Confidence changes are explainable per evidence node.

## Phase 6 — Continuous Evaluation Harness

### Scope
Add a benchmark workflow to measure autonomous quality release-over-release.

### Core Metrics
- Precision of findings.
- Recall on known vulnerable labs.
- False-positive rate.
- Reproducibility score.
- Time-to-evidence.

### Deliverables
- Baseline benchmark suite (small, deterministic targets).
- CI gate with trend reporting.

### Acceptance Criteria
- New changes cannot merge if FP rate regresses beyond threshold.
- Dashboard/report captures metric deltas.

## Initial Sprint Backlog (Start Here)

1. Define role I/O schemas for planner/executor/critic.
2. Add command execution wrapper contract (timeout + provenance fields).
3. Implement run-trace object with Thought/Action/Observation blocks.
4. Add first safety checks: authorized scope + non-destructive mode.
5. Create minimal benchmark scenario and one pass/fail metric.

## Research Basis (for implementation choices)

- ReAct (reasoning + acting): https://arxiv.org/abs/2210.03629
- Toolformer (tool use behavior): https://arxiv.org/abs/2302.04761
- Reflexion (self-improvement loop): https://arxiv.org/abs/2303.11366
- OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/
- NIST SP 800-115: https://csrc.nist.gov/publications/detail/sp/800-115/final
- PTES: http://www.pentest-standard.org/index.php/Main_Page
- FIRST CVSS v3.1: https://www.first.org/cvss/v3-1/specification-document
- MITRE ATT&CK: https://attack.mitre.org/
