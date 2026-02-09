# CortexSec Autonomy Implementation Plan

## Goal
Improve CortexSec's autonomous security workflow with stronger provider compatibility, richer recon, dynamic payload intelligence, and clearer operator feedback.

## Roadmap

### 1) SDK Migration (High)
- Migrate Gemini integration from `google-generativeai` to `google-genai`.
- Keep the existing LLM interface (`generate`, `generate_json`) unchanged so agents do not need provider-specific code.
- Validate with unit tests and a light smoke check through factory creation.

### 2) Dynamic Payloads (High)
- Extend `PayloadAgent` with LLM-generated payload suggestions.
- Keep strict safeguards:
  - only non-destructive payload classes,
  - short payload limits,
  - block obvious exploit/destructive token patterns.
- Combine static baseline payloads with 1-2 contextual dynamic payloads per run.
- Preserve paired-control testing to reduce false positives.

### 3) Recon Expansion (Medium)
- Add lightweight, same-host crawling:
  - seed from target page,
  - follow a small number of discovered links,
  - deduplicate URL set.
- Add directory brute-force discovery using a compact safe wordlist.
- Feed discovered URLs/paths into recon artifacts and downstream attack-surface modeling.

### 4) UX Enhancement: Live Attack Graph (Low)
- Add a CLI flag to enable live attack-graph progress rendering.
- Show current cycle, confirmed paths, and causal completeness in near-real time.
- Keep output fallback simple in non-interactive environments.

## Phased Execution

### Phase A (Immediate)
1. Gemini SDK migration.
2. Dynamic payload generation + guardrails.
3. Recon crawling + directory checks.

### Phase B (Next)
1. Supervisor hooks for live attack-graph snapshots.
2. CLI toggle and rich rendering panel.
3. Documentation examples for operators.

## Success Criteria
- Gemini provider works with latest SDK without interface regressions.
- PayloadAgent reports dynamic payload definitions with safe filtering.
- Recon output includes `crawled_urls` and `directory_hits` on reachable targets.
- Existing test suite remains green and coverage is expanded for new logic.
