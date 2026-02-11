from __future__ import annotations

from cortexsec.api.contracts import AssessmentRequest, AssessmentResult
from cortexsec.api.service import AssessmentService


class CliEngine:
    """Core engine facade consumed by CLI commands."""

    def __init__(self, service: AssessmentService | None = None) -> None:
        self.service = service or AssessmentService()

    def run(self, request: AssessmentRequest) -> AssessmentResult:
        return self.service.execute(request)
