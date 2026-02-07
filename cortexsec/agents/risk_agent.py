from cortexsec.core.agent import BaseAgent, PentestContext


class RiskAgent(BaseAgent):
    """Calculates a simple risk score from findings severity."""

    def __init__(self, llm):
        super().__init__("RiskAgent", llm)

    def run(self, context: PentestContext) -> PentestContext:
        self.log("Calculating risk score...")

        weights = {"Low": 1, "Medium": 3, "High": 6, "Critical": 10}
        total = 0
        for finding in context.findings:
            total += weights.get(finding.severity, 1)

        if total >= 20:
            level = "Critical"
        elif total >= 12:
            level = "High"
        elif total >= 6:
            level = "Medium"
        else:
            level = "Low"

        context.risk_summary = {
            "score": total,
            "level": level,
            "method": "Simple weighted severity model",
            "weights": weights,
        }

        context.history.append(
            {
                "agent": self.name,
                "message": "Risk score calculated",
                "risk_level": level,
                "score": total,
            }
        )
        self.log(f"Risk score complete. Score={total}, Level={level}")
        return context
