import json
import os
from collections import Counter
from cortexsec.core.agent import BaseAgent, PentestContext


class MemoryAgent(BaseAgent):
    """Keeps long-term memory for findings and orchestrator learning."""

    def __init__(self, llm, memory_path: str = "reports/agent_memory.json"):
        super().__init__("MemoryAgent", llm)
        self.memory_path = memory_path

    def _default_memory(self):
        return {
            "total_runs": 0,
            "common_findings": {},
            "recommended_focus": [],
            "orchestrator_policy_scores": {"discovery": 1.0, "validation": 1.0, "convergence": 1.0},
            "reward_history": [],
        }

    def _load_memory(self):
        if not os.path.exists(self.memory_path):
            return self._default_memory()
        try:
            with open(self.memory_path, "r") as f:
                data = json.load(f)
            baseline = self._default_memory()
            baseline.update(data)
            return baseline
        except Exception:
            return self._default_memory()

    def _save_memory(self, memory):
        os.makedirs(os.path.dirname(self.memory_path), exist_ok=True)
        with open(self.memory_path, "w") as f:
            json.dump(memory, f, indent=2)

    def run(self, context: PentestContext) -> PentestContext:
        self.log("Updating agent memory from current findings and learning state...")

        memory = self._load_memory()
        current_titles = [finding.title for finding in context.findings]

        counts = Counter(memory.get("common_findings", {}))
        for title in current_titles:
            counts[title] += 1

        memory["total_runs"] = int(memory.get("total_runs", 0)) + 1
        memory["common_findings"] = dict(counts)
        memory["recommended_focus"] = [title for title, _ in counts.most_common(5)]

        # Persist orchestrator's policy-learning summary
        if context.orchestrator_learning:
            memory["orchestrator_policy_scores"] = context.orchestrator_learning.get(
                "policy_scores", memory.get("orchestrator_policy_scores", {})
            )
            rewards = context.orchestrator_learning.get("reward_history", [])
            memory["reward_history"] = (memory.get("reward_history", []) + rewards)[-50:]

        self._save_memory(memory)
        context.memory = memory

        context.history.append(
            {
                "agent": self.name,
                "message": "Memory updated",
                "top_recurring_findings": memory["recommended_focus"],
                "orchestrator_policy_scores": memory["orchestrator_policy_scores"],
            }
        )

        self.log(f"Memory updated. Total runs recorded: {memory['total_runs']}")
        return context
