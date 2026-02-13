from cortexsec.core.agent import BaseAgent, PentestContext


class ReasoningAgent(BaseAgent):
    """Creates a non-destructive attack graph using causal reasoning."""

    def __init__(self, llm):
        super().__init__("ReasoningAgent", llm)

    def run(self, context: PentestContext) -> PentestContext:
        self.log("Building attack-graph reasoning model...")

        nodes = [{"id": "target", "type": "asset", "label": context.target}]
        edges = []

        for i, finding in enumerate(context.findings, start=1):
            finding.reachable = True
            finding_node_id = f"f{i}"
            impact_node_id = f"impact{i}"
            
            # Track uncertainty based on confidence
            uncertainty = round(1.0 - finding.confidence, 2)

            nodes.append(
                {
                    "id": finding_node_id,
                    "type": "weakness",
                    "label": finding.title,
                    "severity": finding.severity,
                    "reachable": True,
                    "uncertainty": uncertainty,
                }
            )
            
            # Explicit cause-effect rationale
            rationale = finding.impact_summary or "Potential unauthorized access, data exposure, or service disruption"
            
            nodes.append(
                {
                    "id": impact_node_id,
                    "type": "impact",
                    "label": rationale,
                    "cause": finding.title,
                }
            )
            edges.append({"from": "target", "to": finding_node_id, "relation": "has_weakness"})
            edges.append({
                "from": finding_node_id, 
                "to": impact_node_id, 
                "relation": "can_lead_to",
                "rationale": f"Exploitation of {finding.title} leads to {rationale}"
            })

            # 2026 Logic: Attack Chaining
            # If critical, infer a derived attack path (e.g., lateral movement or API abuse)
            if finding.severity == "Critical":
                chained_node_id = f"chain_{i}"
                nodes.append({
                    "id": chained_node_id,
                    "type": "impact", 
                    "label": "Lateral Movement / API Abuse (Derived)",
                    "severity": "High",
                    "uncertainty": min(1.0, uncertainty + 0.2)
                })
                edges.append({
                    "from": impact_node_id, 
                    "to": chained_node_id, 
                    "relation": "enables_chaining",
                    "rationale": "Critical impact allows for further exploitation of internal resources"
                })

        weakness_nodes = [n for n in nodes if n["type"] == "weakness"]
        impact_nodes = [n for n in nodes if n["type"] == "impact"]
        causal_completeness = round((len(impact_nodes) / len(weakness_nodes)), 3) if weakness_nodes else 1.0

        context.attack_graph = {
            "nodes": nodes,
            "edges": edges,
            "confirmed_paths": len(impact_nodes),
            "causal_completeness": causal_completeness,
            "explainability": "Every reachable weakness has an explicit causal path to business impact.",
        }
        context.history.append(
            {
                "agent": self.name,
                "message": "Attack graph generated",
                "node_count": len(nodes),
                "confirmed_paths": len(impact_nodes),
                "causal_completeness": causal_completeness,
            }
        )
        self.log(f"Attack graph generated with {len(nodes)} nodes (causal_completeness={causal_completeness}).")
        return context
