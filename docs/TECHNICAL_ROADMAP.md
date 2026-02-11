# CortexSec Technical Roadmap (Production Track)

## Architecture Direction: Hybrid CLI + GUI

CortexSec will follow a **hybrid interface architecture** where:
- **CLI remains the core execution engine** for automation, CI/CD, and repeatable security workflows.
- **GUI remains a thin client** over the same API/service layer for visualization, triage, and operator onboarding.

### Why hybrid (industry-grounded rationale)

Security tooling in practice is hybrid. Mature platforms (for example, Burp Suite and similar ecosystems) pair strong GUI ergonomics with scriptable automation layers. Industry usage patterns repeatedly show advanced users still favor scriptability and reproducibility; a practical assumption used for roadmap planning is that a majority of power users remain CLI-centric (often cited around ~70% in practitioner communities and training cohorts), while GUI usage increases adoption among mixed-skill teams.

For CortexSec, this means:
1. Keep deterministic, auditable pipelines in CLI first.
2. Add GUI capabilities that accelerate visualization and reduce context-switch overhead.
3. Preserve one shared API contract so behavior is identical across interfaces.

> Expected impact (hypothesis): hybrid delivery can provide **probabilistic 2–3× efficiency gains** in assessment workflows by reducing friction in evidence review, attack-path visualization, and analyst onboarding while preserving automation and scripting.

## Risk & Adoption Reality Check

Without empirical benchmarks and external community validation, adoption can remain low even when architecture is technically sound.

### Adoption risks
- Missing independent benchmark data versus incumbent tools.
- Unclear operator ROI in real team workflows.
- Feature breadth may outpace trust if observability and governance are not validated in the field.

### Phased rollout strategy

1. **Community validation (Phase A)**
   - Beta tester program (security engineers + red team practitioners)
   - Open-source contributor feedback loops
   - Benchmark studies on representative targets
   - Opt-in telemetry for latency, failure rates, and workflow completion

2. **Stabilization (Phase B)**
   - Backward compatibility hardening
   - Plugin API freeze for extension ecosystem
   - Governance controls (policy, approvals, replay)

3. **Enterprise rollout (Phase C)**
   - Deployment guides for regulated environments
   - Security review artifacts and threat model publication
   - Operational SLOs and maintenance commitments

## Planned Milestones

- M1: Shared API/service orchestration layer for both CLI and GUI.
- M2: Plugin architecture with scanner/analyzer contracts.
- M3: Structured runtime logging + forensic audit parity.
- M4: Telemetry/benchmark framework for external validation.
- M5: GUI triage workflows built as a thin wrapper over API.
