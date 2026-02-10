from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from cortexsec.llm.base import BaseLLM
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("cortexsec")


class Finding(BaseModel):
    """Represents a single security finding."""
    title: str
    description: str
    severity: str  # Low, Medium, High, Critical
    confidence: float  # 0.0 to 1.0
    evidence: str
    mitigation: Optional[str] = None
    cvss_score: Optional[float] = None
    owasp_mapping: Optional[str] = None
    mitre_mapping: Optional[str] = None
    impact_summary: Optional[str] = None
    exploitability_summary: Optional[str] = None
    exploitability_confidence: float = 0.0
    reachable: bool = True
    analyzed: bool = False


class PentestContext(BaseModel):
    """Shared state across all agents."""
    target: str
    mode: str = "lab"
    findings: List[Finding] = Field(default_factory=list)
    recon_data: Dict[str, Any] = Field(default_factory=dict)
    attack_surface: Dict[str, Any] = Field(default_factory=dict)
    attack_graph: Dict[str, Any] = Field(default_factory=dict)
    risk_summary: Dict[str, Any] = Field(default_factory=dict)
    exploitability_assessment: Dict[str, Any] = Field(default_factory=dict)
    attack_simulation: List[Dict[str, Any]] = Field(default_factory=list)
    payload_tests: List[Dict[str, Any]] = Field(default_factory=list)
    memory: Dict[str, Any] = Field(default_factory=dict)
    orchestrator_learning: Dict[str, Any] = Field(default_factory=dict)
    assessment_metrics: Dict[str, Any] = Field(default_factory=dict)
    scientific_analysis: Dict[str, Any] = Field(default_factory=dict)
    remediation_plan: Dict[str, Any] = Field(default_factory=dict)
    stop_reason: str = ""
    history: List[Dict[str, Any]] = Field(default_factory=list)
    continuous_improvement: bool = False
    require_findings_before_stop: bool = False
    max_no_finding_extensions: int = 3
    pro_user: bool = False
    destructive_mode: bool = False


class BaseAgent:
    """Base class for all specialized agents."""

    def __init__(self, name: str, llm: BaseLLM):
        self.name = name
        self.llm = llm

    def log(self, message: str):
        logger.info(f"[{self.name}] {message}")

    def run(self, context: PentestContext) -> PentestContext:
        raise NotImplementedError("Subclasses must implement run()")
