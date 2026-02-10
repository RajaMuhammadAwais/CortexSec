from dataclasses import dataclass
from typing import Dict, Set, Tuple


@dataclass(frozen=True)
class AgentSkill:
    """Small, reusable skill unit inspired by skill-card style workflows."""

    name: str
    trigger: str
    outcome: str


SKILL_CATALOG: Dict[str, Tuple[AgentSkill, ...]] = {
    "planner": (
        AgentSkill("Threat Modeling", "new assessment goal", "defines objective, constraints, and risks"),
        AgentSkill("Task Decomposition", "complex user request", "splits work into clear next actions"),
        AgentSkill("Priority Scheduling", "multiple pending tasks", "orders work by risk and dependency"),
    ),
    "recon": (
        AgentSkill("Attack Surface Mapping", "target scope provided", "identifies entry points and exposed assets"),
        AgentSkill("OSINT Fingerprinting", "domain or service details needed", "collects non-intrusive intelligence"),
        AgentSkill("Service Enumeration", "host/service requires detail", "summarizes observable services and metadata"),
    ),
    "executor": (
        AgentSkill("Safe Command Execution", "validated task received", "runs non-destructive, planned checks"),
        AgentSkill("Validation Probing", "finding needs confirmation", "tests assumptions with lightweight probes"),
        AgentSkill("Evidence Collection", "result produced", "stores command/result evidence for audit"),
    ),
    "reviewer": (
        AgentSkill("Finding Verification", "new evidence available", "confirms result quality and consistency"),
        AgentSkill("False-Positive Reduction", "signal appears weak", "requests stronger proof before acceptance"),
        AgentSkill("Risk Calibration", "impact is discussed", "aligns severity and confidence with evidence"),
    ),
    "memory": (
        AgentSkill("Session Recall", "context continues", "restores relevant history for the active context"),
        AgentSkill("Pattern Linking", "similar events appear", "connects related findings across turns"),
        AgentSkill("Context Deduplication", "duplicate work risk", "flags repeated effort and preserves unique updates"),
    ),
}


def skills_for_role(role: str) -> Tuple[str, ...]:
    """Return skill names for a role."""
    return tuple(skill.name for skill in SKILL_CATALOG.get(role, ()))


def validate_unique_role_skills() -> None:
    """Ensure each role owns distinct skill names to avoid role-overlap confusion."""
    seen: Set[str] = set()
    duplicates: Set[str] = set()

    for role in SKILL_CATALOG:
        for skill in skills_for_role(role):
            if skill in seen:
                duplicates.add(skill)
            seen.add(skill)

    if duplicates:
        duplicate_list = ", ".join(sorted(duplicates))
        raise ValueError(f"Duplicate skills found across roles: {duplicate_list}")
