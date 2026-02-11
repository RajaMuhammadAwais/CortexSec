# CortexSec Hybrid Architecture

## Project folder structure (new production modules)

```text
cortexsec/
  api/
    contracts.py        # shared request/response contracts
    service.py          # shared application service used by CLI + GUI
  app/
    config.py           # file/env-driven configuration
    logging_config.py   # structured runtime logging setup
  engine/
    cli_engine.py       # core CLI engine facade
  gui/
    tk_app.py           # thin GUI wrapper over shared API
  plugins/
    base.py             # plugin interfaces and registry
    builtin.py          # built-in scanner plugins (nmap/zap)
  telemetry/
    benchmark.py        # benchmark and telemetry recorder stub
```

## Design principles

- **CLI-first core**: no GUI-only logic in scanning/execution pipeline.
- **Shared API layer**: both interfaces call the same `AssessmentService`.
- **Dependency inversion**: plugins depend on abstractions (`SecurityPlugin`), not concrete CLI code.
- **Operational observability**: structured logs + forensic audit artifacts + benchmark stubs.
- **Secure defaults**: optional heavy behaviors (external scanners) remain opt-in.

## Execution flow

1. CLI/GUI collects user input.
2. Input mapped into `AssessmentRequest`.
3. `AssessmentService.execute()` performs:
   - sandbox guard (optional)
   - plugin execution (optional)
   - multi-agent orchestration
   - telemetry snapshot and audit logging
4. Interface receives `AssessmentResult` and renders output.

This keeps the GUI thin and avoids logic drift between interfaces.
