from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

import requests

from cortexsec.core.agent import BaseAgent, PentestContext


@dataclass
class PayloadSpec:
    payload_type: str
    value: str
    goal: str
    hypothesis: str


class PayloadAgent(BaseAgent):
    """Runs real-world (non-destructive) payload tests against discovered HTTP entry-points."""

    def __init__(self, llm, timeout: int = 8):
        super().__init__("PayloadAgent", llm)
        self.timeout = timeout

    def _payloads(self) -> List[PayloadSpec]:
        return [
            PayloadSpec(
                payload_type="canary",
                value="CORTEX_CANARY_02_b91c",
                goal="Input flow tracing",
                hypothesis="A reflected marker suggests weak output handling or unsanitized reflection paths.",
            ),
            PayloadSpec(
                payload_type="fuzz-boundary",
                value="A" * 8192,
                goal="Boundary validation",
                hypothesis="Oversized inputs may trigger inconsistent validation or parser behavior.",
            ),
            PayloadSpec(
                payload_type="fuzz-boundary",
                value="%00%0a%0d%F0%9F%92%A5",
                goal="Encoding and parser consistency",
                hypothesis="If canonicalization is inconsistent, encoded and mixed-byte inputs may alter response patterns.",
            ),
            PayloadSpec(
                payload_type="logic-test",
                value='{"role":"admin","account_id":"other-tenant"}',
                goal="Authorization boundary checks",
                hypothesis="Role/tenant mismatch values may reveal missing authorization checks.",
            ),
            PayloadSpec(
                payload_type="logic-test",
                value="state=approved&workflow_step=final",
                goal="State manipulation checks",
                hypothesis="If state transitions are weakly enforced, direct state-jump values may alter behavior.",
            ),
        ]

    def _is_http_target(self, target: str) -> bool:
        parsed = urlparse(target)
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)

    def _entry_points(self, context: PentestContext) -> List[str]:
        discovered = context.attack_surface.get("entry_points", [])
        target = context.target.rstrip("/")
        endpoints = [target]

        for item in discovered:
            if not isinstance(item, str) or not item:
                continue
            if item.startswith("http://") or item.startswith("https://"):
                endpoints.append(item)
            elif item.startswith("/"):
                endpoints.append(urljoin(target + "/", item.lstrip("/")))

        # preserve order + uniqueness
        return list(dict.fromkeys(endpoints))[:5]

    def _baseline(self, url: str) -> Dict[str, Any]:
        baseline = {"status_code": None, "body_length": 0}
        try:
            response = requests.get(url, timeout=self.timeout)
            baseline["status_code"] = response.status_code
            baseline["body_length"] = len(response.text or "")
        except Exception:  # noqa: BLE001
            pass
        return baseline

    def _run_vector(self, url: str, payload: PayloadSpec, vector: str, baseline: Dict[str, Any]) -> Dict[str, Any]:
        result = {
            "endpoint": url,
            "payload_type": payload.payload_type,
            "payload": payload.value,
            "goal": payload.goal,
            "hypothesis": payload.hypothesis,
            "request_mode": vector,
            "observed": "not-run",
            "status": "inconclusive",
            "reasoning": "",
            "evidence": {},
        }

        try:
            if vector == "query":
                response = requests.get(url, params={"q": payload.value}, timeout=self.timeout)
            elif vector == "json":
                response = requests.post(url, json={"input": payload.value}, timeout=self.timeout)
            elif vector == "form":
                response = requests.post(url, data={"input": payload.value}, timeout=self.timeout)
            else:  # header/auth-boundary
                response = requests.get(
                    url,
                    headers={"X-User-Role": "user", "X-Requested-Role": "admin", "X-Pentest-Input": payload.value},
                    timeout=self.timeout,
                )

            body = response.text or ""
            status_changed = baseline.get("status_code") is not None and baseline.get("status_code") != response.status_code
            length_changed = abs(len(body) - int(baseline.get("body_length", 0))) > 200
            canary_reflected = payload.value in body
            auth_signal = response.status_code in {401, 403} or any(
                token in body.lower() for token in ["forbidden", "unauthorized", "permission", "access denied"]
            )

            result["observed"] = "response-received"
            result["evidence"] = {
                "baseline_status": baseline.get("status_code"),
                "payload_status": response.status_code,
                "baseline_body_length": baseline.get("body_length", 0),
                "payload_body_length": len(body),
                "status_changed": status_changed,
                "length_changed": length_changed,
                "canary_reflected": canary_reflected,
                "authorization_signal": auth_signal,
            }

            if status_changed or length_changed or canary_reflected:
                result["status"] = "needs-review"
                result["reasoning"] = (
                    "Real endpoint behavior changed under non-destructive payload injection. "
                    "Review for validation, logic, or authorization control weaknesses."
                )
            else:
                result["status"] = "no-strong-signal"
                result["reasoning"] = "No significant behavior delta observed."

        except Exception as exc:  # noqa: BLE001
            result["observed"] = "request-error"
            result["status"] = "inconclusive"
            result["reasoning"] = f"Request execution error: {exc}"

        return result

    def run(self, context: PentestContext) -> PentestContext:
        self.log("Running real-world payload injection tests (non-destructive) against live entry points...")

        if context.destructive_mode:
            context.history.append({
                "agent": self.name,
                "message": "Destructive mode requested: execution blocked; planning metadata only",
                "policy": "No destructive payload execution by design",
            })

        if not self._is_http_target(context.target):
            context.history.append({"agent": self.name, "message": "Skipped payload tests (non-HTTP target)"})
            return context

        results: List[Dict[str, Any]] = []
        vectors = ["query", "json", "form", "header-auth"]

        for endpoint in self._entry_points(context):
            baseline = self._baseline(endpoint)
            for payload in self._payloads():
                for vector in vectors:
                    results.append(self._run_vector(endpoint, payload, vector, baseline))

        context.payload_tests = results
        high_signal = [r for r in results if r.get("status") == "needs-review"]
        context.history.append(
            {
                "agent": self.name,
                "message": "Payload testing completed",
                "tests_run": len(results),
                "signals": len(high_signal),
                "execution_mode": "real-world",
            }
        )
        self.log(f"Payload tests executed: {len(results)} | signals: {len(high_signal)}")
        return context
