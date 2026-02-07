# CortexSec Multi-Agent Architecture Graph

```mermaid
flowchart TD
    A[CLI Start] --> B[Supervisor / Orchestrator]
    B --> C[ReconAgent]
    C --> D[AttackSurfaceAgent]
    D --> E[VulnAnalysisAgent]
    E --> F[ReasoningAgent]
    F --> G[ExploitabilityAgent]
    G --> H[RiskAgent]
    H --> I[AttackSimulationAgent]
    I --> J[MemoryAgent]
    J --> K{Stop Criteria Met?}
    K -- No --> C
    K -- Yes --> L[ReportAgent]
    L --> M[Markdown Report]

    N[(OWASP / CVSS / MITRE)] --> L
```
