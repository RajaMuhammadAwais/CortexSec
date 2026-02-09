from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
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
                value="CORTEX_CANARY_03_f4ad",
                goal="Input flow tracing",
                hypothesis="A reflected marker suggests unsanitized reflection path exposure.",
            ),
            PayloadSpec(
                payload_type="fuzz-boundary",
                value="A" * 8192,
                goal="Boundary validation",
                hypothesis="Oversized inputs may reveal weak length and parser guards.",
            ),
            PayloadSpec(
                payload_type="fuzz-boundary",
                value="%00%0a%0d%F0%9F%92%A5",
                goal="Encoding and parser consistency",
                hypothesis="Encoding edge-cases can expose inconsistent canonicalization.",
            ),
            PayloadSpec(
                payload_type="logic-test",
                value='{"role":"admin","account_id":"other-tenant"}',
                goal="Authorization boundary checks",
                hypothesis="Role/tenant mismatch may reveal authorization boundary weaknesses.",
            ),
            PayloadSpec(
                payload_type="logic-test",
                value="state=approved&workflow_step=final",
                goal="State manipulation checks",
                hypothesis="Direct state-jump values may bypass workflow enforcement.",
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

    def _execute_vector(self, url: str, vector: str, value: str):
        if vector == "query":
            return requests.get(url, params={"q": value}, timeout=self.timeout)
        if vector == "json":
            return requests.post(url, json={"input": value}, timeout=self.timeout)
        if vector == "form":
            return requests.post(url, data={"input": value}, timeout=self.timeout)
        return requests.get(
            url,
            headers={"X-User-Role": "user", "X-Requested-Role": "admin", "X-Pentest-Input": value},
            timeout=self.timeout,
        )

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
            # Experimental design: payload request + paired negative control request.
            payload_response = self._execute_vector(url, vector, payload.value)
            control_response = self._execute_vector(url, vector, "CORTEX_CTRL_NEUTRAL")

            body = payload_response.text or ""
            control_body = control_response.text or ""

            status_changed = baseline.get("status_code") is not None and baseline.get("status_code") != payload_response.status_code
            length_changed = abs(len(body) - int(baseline.get("body_length", 0))) > 200
            canary_reflected = payload.value in body
            auth_signal = payload_response.status_code in {401, 403} or any(
                token in body.lower() for token in ["forbidden", "unauthorized", "permission", "access denied"]
            )

            control_status_changed = baseline.get("status_code") is not None and baseline.get("status_code") != control_response.status_code
            control_length_changed = abs(len(control_body) - int(baseline.get("body_length", 0))) > 200
            control_auth_signal = control_response.status_code in {401, 403} or any(
                token in control_body.lower() for token in ["forbidden", "unauthorized", "permission", "access denied"]
            )

            perturbation_score = 0
            perturbation_score += 1 if status_changed and not control_status_changed else 0
            perturbation_score += 1 if length_changed and not control_length_changed else 0
            perturbation_score += 1 if canary_reflected else 0
            perturbation_score += 1 if auth_signal and not control_auth_signal else 0

            reproducible: Optional[bool] = None
            if perturbation_score >= 2:
                replay_response = self._execute_vector(url, vector, payload.value)
                replay_body = replay_response.text or ""
                replay_length_changed = abs(len(replay_body) - int(baseline.get("body_length", 0))) > 200
                replay_canary = payload.value in replay_body
                replay_auth_signal = replay_response.status_code in {401, 403} or any(
                    token in replay_body.lower() for token in ["forbidden", "unauthorized", "permission", "access denied"]
                )
                reproducible = (
                    replay_response.status_code == payload_response.status_code
                    and replay_length_changed == length_changed
                    and replay_canary == canary_reflected
                    and replay_auth_signal == auth_signal
                )

            result["observed"] = "response-received"
            result["evidence"] = {
                "baseline_status": baseline.get("status_code"),
                "payload_status": payload_response.status_code,
                "control_status": control_response.status_code,
                "baseline_body_length": baseline.get("body_length", 0),
                "payload_body_length": len(body),
                "control_body_length": len(control_body),
                "status_changed": status_changed,
                "length_changed": length_changed,
                "control_status_changed": control_status_changed,
                "control_length_changed": control_length_changed,
                "control_authorization_signal": control_auth_signal,
                "canary_reflected": canary_reflected,
                "authorization_signal": auth_signal,
                "perturbation_score": perturbation_score,
                "reproducible": reproducible,
            }

            if perturbation_score >= 2:
                result["status"] = "needs-review"
                result["reasoning"] = (
                    "Payload produced stronger perturbation than paired neutral control. "
                    "Potential validation/logic/auth weakness; confirm manually."
                )
            elif perturbation_score == 1:
                result["status"] = "weak-signal"
                result["reasoning"] = "Single weak anomaly observed; treat as low-confidence signal."
            else:
                result["status"] = "no-strong-signal"
                result["reasoning"] = "No payload-specific perturbation over control baseline."

        except Exception as exc:  # noqa: BLE001
            result["observed"] = "request-error"
            result["status"] = "inconclusive"
            result["reasoning"] = f"Request execution error: {exc}"

        return result

    def run(self, context: PentestContext) -> PentestContext:
        self.log("Running real-world payload injection tests (non-destructive) against live entry points...")

        if context.destructive_mode:
            context.history.append(
                {
                    "agent": self.name,
                    "message": "Destructive mode requested: execution blocked; planning metadata only",
                    "policy": "No destructive payload execution by design",
                }
            )

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
        weak_signal = [r for r in results if r.get("status") == "weak-signal"]
        context.history.append(
            {
                "agent": self.name,
                "message": "Payload testing completed",
                "tests_run": len(results),
                "signals": len(high_signal),
                "weak_signals": len(weak_signal),
                "execution_mode": "real-world",
                "design": "paired-control perturbation testing",
            }
        )
        self.log(f"Payload tests executed: {len(results)} | strong: {len(high_signal)} | weak: {len(weak_signal)}")
        return context
