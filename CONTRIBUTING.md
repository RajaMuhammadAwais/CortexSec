# Contributing to CortexSec

Thanks for your interest in contributing to CortexSec. This guide explains how to contribute safely and effectively to this open-source security project.

## 1) Core Principles

- **Authorized-use only**: never test targets without explicit permission.
- **Non-destructive by default**: changes and test logic should preserve system safety.
- **Evidence-driven quality**: prefer reproducible checks and clear rationale.
- **Respectful collaboration**: constructive reviews and clear communication.

## 2) Development Setup

```bash
git clone https://github.com/RajaMuhammadAwais/CortexSec.git
cd CortexSec
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

Optional dev tools:

```bash
pip install -U pytest ruff black
```

## 3) Branching & Commit Style

- Create a feature branch from the latest main branch.
- Keep pull requests focused and small when possible.
- Use clear commit messages, e.g.:
  - `feat: add X capability`
  - `fix: resolve Y bug`
  - `docs: improve Z documentation`

## 4) Code Quality Expectations

Before opening a PR, run relevant checks locally:

```bash
pytest -q
python -m compileall cortexsec
```

If your change is documentation-only, explain why no runtime tests were required.

## 5) Documentation Requirements

For user-facing behavior changes, update related docs (such as `README.md`, `USER_GUIDE.md`, or files in `docs/`).

When adding architecture updates, include:

- role/responsibility changes,
- data/evidence flow impact,
- any safety or policy implications.

## 6) Pull Request Checklist

Please include:

- **What changed** and **why**.
- **How to validate** (commands and expected outcomes).
- Any limitations or follow-up work.

Suggested checklist:

- [ ] Code is scoped to the issue/request.
- [ ] Tests/checks were run and documented.
- [ ] Docs were updated if behavior changed.
- [ ] No destructive or unauthorized security logic introduced.

## 7) Security & Responsible Disclosure

If you discover a security issue in CortexSec itself, do not publish exploit details in a public issue. Use responsible disclosure through project maintainers.

## 8) Code of Conduct

Be professional and respectful. Good-faith technical disagreement is welcome; personal attacks are not.

---

Thank you for helping improve CortexSec.
