from cortexsec.core.agent import BaseAgent, PentestContext


class AttackSimulationAgent(BaseAgent):
    """
    Creates safe exploit simulation playbooks (no automatic exploitation).
    """

    def __init__(self, llm):
        super().__init__("AttackSimulationAgent", llm)

    def run(self, context: PentestContext) -> PentestContext:
        self.log("Building safe attack simulation plan from findings...")
        simulations = []

        for finding in context.findings:
            simulations.append(
                {
                    "finding_title": finding.title,
                    "severity": finding.severity,
                    "simulation_goal": f"Validate whether '{finding.title}' can be reproduced safely in a controlled lab.",
                    "manual_steps": [
                        "Create a staging copy of the target (never production).",
                        "Use synthetic/non-sensitive test accounts and data.",
                        "Attempt a minimal proof-of-concept to confirm the weakness only.",
                        "Record logs and stop immediately after validation.",
                    ],
                    "safety_rules": [
                        "Use real-world but non-destructive payload checks only; never execute destructive actions.",
                        "Do not automate exploitation against unauthorized targets.",
                        "Get written authorization before any active testing.",
                    ],
                    "destructive_mode": context.destructive_mode,
                    "destructive_plan": (
                        [
                            "Plan-only: define rollback steps and snapshot strategy.",
                            "Require written approval and maintenance window.",
                            "Never auto-execute destructive payloads from CortexSec runtime.",
                        ]
                        if context.destructive_mode
                        else []
                    ),
                }
            )

        context.attack_simulation = simulations
        context.history.append(
            {
                "agent": self.name,
                "message": "Safe attack simulation plan created",
                "count": len(simulations),
            }
        )
        self.log(f"Prepared {len(simulations)} simulation playbooks.")
        return context
