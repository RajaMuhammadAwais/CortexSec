from urllib.parse import urljoin, urlparse

import requests

from cortexsec.agents.real_world_guidance import real_world_prompt
from cortexsec.core.agent import BaseAgent, PentestContext


class ReconAgent(BaseAgent):
    """Agent responsible for initial reconnaissance."""

    def __init__(self, llm):
        super().__init__("ReconAgent", llm)

    def _is_same_host(self, base_url: str, candidate: str) -> bool:
        base_host = urlparse(base_url).netloc
        candidate_host = urlparse(candidate).netloc
        return candidate_host == base_host

    def _extract_links(self, html: str, base_url: str):
        links = []
        for token in html.split("href="):
            if not token:
                continue
            quote = '"' if token.startswith('"') else "'" if token.startswith("'") else None
            if not quote:
                continue
            raw = token[1:].split(quote)[0].strip()
            if not raw or raw.startswith("#") or raw.startswith("javascript:"):
                continue
            absolute = urljoin(base_url, raw)
            if self._is_same_host(base_url, absolute):
                links.append(absolute)
        return list(dict.fromkeys(links))[:20]

    def _crawl(self, target: str, timeout: int = 8):
        discovered = []
        try:
            response = requests.get(target, timeout=timeout)
            discovered.extend(self._extract_links(response.text or "", target))
        except Exception:
            return discovered

        for link in list(discovered)[:5]:
            try:
                sub = requests.get(link, timeout=timeout)
                discovered.extend(self._extract_links(sub.text or "", link))
            except Exception:
                continue

        return list(dict.fromkeys(discovered))[:25]

    def _dir_bruteforce(self, target: str, timeout: int = 6):
        words = [
            "admin",
            "login",
            "api",
            "dashboard",
            "uploads",
            "backup",
            "docs",
            "swagger",
        ]
        found = []
        for word in words:
            candidate = urljoin(target.rstrip("/") + "/", word)
            try:
                response = requests.get(candidate, timeout=timeout)
                if response.status_code < 400:
                    found.append({"path": f"/{word}", "status": response.status_code})
            except Exception:
                continue
        return found

    def run(self, context: PentestContext) -> PentestContext:
        self.log(f"Performing reconnaissance on {context.target}")

        recon_results = {}

        try:
            response = requests.get(context.target, timeout=10)
            recon_results["headers"] = dict(response.headers)
            recon_results["status_code"] = response.status_code
            recon_results["server"] = response.headers.get("Server", "Unknown")
            recon_results["tech_stack"] = response.headers.get("X-Powered-By", "Unknown")
        except Exception as e:
            recon_results["error"] = f"Failed to reach target: {str(e)}"

        crawled_urls = self._crawl(context.target)
        brute_force_hits = self._dir_bruteforce(context.target)
        recon_results["crawled_urls"] = crawled_urls
        recon_results["directory_hits"] = brute_force_hits

        analysis_prompt = f"""
        Analyze the following reconnaissance data for {context.target}:
        {recon_results}

        Identify potential technologies, versions, and interesting headers that might indicate vulnerabilities.
        Return the analysis in JSON format with keys: 'technologies', 'potential_issues', 'next_steps'.
        """

        llm_analysis = self.llm.generate_json(
            analysis_prompt,
            system_prompt=real_world_prompt("reconnaissance expert"),
        )
        context.recon_data = {"raw": recon_results, "analysis": llm_analysis}

        self.log("Reconnaissance complete.")
        return context
