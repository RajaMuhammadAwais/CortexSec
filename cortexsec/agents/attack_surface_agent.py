from urllib.parse import urlparse
from cortexsec.core.agent import BaseAgent, PentestContext


class AttackSurfaceAgent(BaseAgent):
    """Builds a simple attack-surface model from recon data."""

    def __init__(self, llm):
        super().__init__("AttackSurfaceAgent", llm)

    def run(self, context: PentestContext) -> PentestContext:
        parsed = urlparse(context.target)
        headers = context.recon_data.get("raw", {}).get("headers", {})

        exposed_services = []
        vectors = ["web"]

        if headers.get("Server"):
            exposed_services.append(f"web-server:{headers.get('Server')}")
        if headers.get("X-Powered-By"):
            exposed_services.append(f"app-framework:{headers.get('X-Powered-By')}")
        
        # 2026 Logic: API Discovery & Multi-vector
        if "api" in context.target or "json" in str(headers).lower():
            vectors.append("api")
            exposed_services.append("api-endpoint")
        
        if "cloud" in str(headers).lower():
            vectors.append("cloud")

        context.attack_surface = {
            "entry_points": [context.target],
            "host": parsed.hostname,
            "scheme": parsed.scheme,
            "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            "technologies": context.recon_data.get("analysis", {}).get("technologies", []),
            "exposed_services": exposed_services,
            "vectors": vectors,
        }

        context.history.append({"agent": self.name, "message": "Attack surface modeled"})
        self.log("Attack surface model updated.")
        return context
