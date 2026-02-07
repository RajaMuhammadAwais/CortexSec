from cortexsec.core.agent import BaseAgent, PentestContext
import requests
from typing import Dict, Any

class ReconAgent(BaseAgent):
    """
    Agent responsible for initial reconnaissance.
    """
    def __init__(self, llm):
        super().__init__("ReconAgent", llm)

    def run(self, context: PentestContext) -> PentestContext:
        self.log(f"Performing reconnaissance on {context.target}")
        
        recon_results = {}
        
        # Simulated HTTP header analysis
        try:
            response = requests.get(context.target, timeout=10)
            recon_results["headers"] = dict(response.headers)
            recon_results["status_code"] = response.status_code
            recon_results["server"] = response.headers.get("Server", "Unknown")
            recon_results["tech_stack"] = response.headers.get("X-Powered-By", "Unknown")
        except Exception as e:
            recon_results["error"] = f"Failed to reach target: {str(e)}"

        # Use LLM to analyze recon data
        analysis_prompt = f"""
        Analyze the following reconnaissance data for {context.target}:
        {recon_results}
        
        Identify potential technologies, versions, and interesting headers that might indicate vulnerabilities.
        Return the analysis in JSON format with keys: 'technologies', 'potential_issues', 'next_steps'.
        """
        
        llm_analysis = self.llm.generate_json(analysis_prompt, system_prompt="You are a reconnaissance expert.")
        context.recon_data = {
            "raw": recon_results,
            "analysis": llm_analysis
        }
        
        self.log("Reconnaissance complete.")
        return context
