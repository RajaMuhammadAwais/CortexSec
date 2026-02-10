from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Deque, Dict, Iterable, List, Optional, Set, Tuple
import random
import time

from cortexsec.core.agent_skills import skills_for_role


VALID_INTENTS = {"question", "task", "info", "feedback"}


@dataclass
class AgentMessage:
    """Standard message format for agent-to-agent communication."""

    sender: str
    receivers: List[str]
    intent: str
    content: str
    timestamp: datetime
    context_id: str
    turn_id: int


class MessageBus:
    """Simple in-memory FIFO bus used by the orchestrator."""

    def __init__(self):
        self._queue: Deque[AgentMessage] = deque()

    def publish(self, message: AgentMessage):
        self._queue.append(message)

    def has_messages(self) -> bool:
        return bool(self._queue)

    def pop(self) -> AgentMessage:
        return self._queue.popleft()

    def __len__(self) -> int:
        return len(self._queue)


@dataclass(frozen=True)
class RoleProfile:
    role: str
    emoji: str
    responsibilities: Tuple[str, ...]
    skills: Tuple[str, ...]


class CommunicatingAgent:
    """Role-based agent with short-term and per-context long-term memory."""

    def __init__(
        self,
        name: str,
        profile: RoleProfile,
        short_memory_size: int = 8,
        delay_range: Tuple[float, float] = (0.08, 0.18),
    ):
        self.name = name
        self.profile = profile
        self.short_term_memory: Deque[AgentMessage] = deque(maxlen=short_memory_size)
        self.long_term_memory: Dict[str, List[AgentMessage]] = defaultdict(list)
        self.delay_range = delay_range

    def can_receive(self, message: AgentMessage) -> bool:
        normalized = {receiver.lower() for receiver in message.receivers}
        return "all" in normalized or self.name.lower() in normalized or self.profile.role in normalized

    def remember(self, message: AgentMessage):
        self.short_term_memory.append(message)
        self.long_term_memory[message.context_id].append(message)

    def infer_intent(self, message: AgentMessage) -> str:
        normalized_intent = message.intent.lower().strip()
        content = message.content.lower()

        if "?" in content or any(token in content for token in ("why", "how", "what", "can you")):
            return "question"
        if any(token in content for token in ("do ", "run ", "start", "execute", "please", "next step", "plan")):
            return "task"
        if any(token in content for token in ("feedback", "review", "improve", "validate")):
            return "feedback"
        if normalized_intent in VALID_INTENTS:
            return normalized_intent
        return "info"

    def decide_action(self, message: AgentMessage) -> str:
        if message.sender == self.name:
            return "ignore"

        intent = self.infer_intent(message)
        role = self.profile.role

        if role == "memory":
            return "store" if intent in {"info", "feedback"} else "reply"

        if intent == "task" and role in {"planner", "recon", "executor"}:
            return "reply"
        if intent == "question" and role in {"planner", "reviewer", "memory"}:
            return "reply"
        if intent == "feedback" and role in {"reviewer", "planner"}:
            return "reply"

        if role == "planner" and intent == "info":
            return "delegate"

        return "store" if role in {"reviewer", "recon"} else "ignore"

    def _context_seen_count(self, context_id: str) -> int:
        return len(self.long_term_memory.get(context_id, []))

    def _sleep_for_realism(self):
        delay_min, delay_max = self.delay_range
        time.sleep(random.uniform(delay_min, delay_max))

    def pick_skill(self, intent: str, content: str) -> str:
        """Select a role skill with lightweight matching against intent/content."""
        lowered = content.lower()
        for skill in self.profile.skills:
            skill_lower = skill.lower()
            if any(token in skill_lower for token in lowered.split()):
                return skill

        by_intent = {
            "task": 0,
            "question": 1,
            "feedback": 2,
            "info": -1,
        }
        if not self.profile.skills:
            return "general"
        return self.profile.skills[by_intent.get(intent, 0) % len(self.profile.skills)]

    def generate_response(self, message: AgentMessage) -> Optional[Tuple[str, str, List[str]]]:
        action = self.decide_action(message)
        if action == "ignore":
            return None

        self._sleep_for_realism()
        context_count = self._context_seen_count(message.context_id)
        inferred_intent = self.infer_intent(message)
        chosen_skill = self.pick_skill(inferred_intent, message.content)

        if action == "store":
            reason = "I am recording this in shared memory before acting"
            response = (
                f"{reason}. Skill used: {chosen_skill}. "
                f"I now have {context_count} messages saved for context {message.context_id}."
            )
            return "info", response, ["planner"]

        if action == "delegate":
            reason = "I reviewed the update and split work for specialists"
            response = f"{reason}. Skill used: {chosen_skill}. Recon, collect evidence first for: {message.content}"
            return "task", response, ["recon"]

        role = self.profile.role
        if role == "planner":
            reason = "I created a human-style plan with clear role boundaries"
            response = f"{reason}. Skill used: {chosen_skill}. Recon first: gather facts for task -> {message.content}"
            return "task", response, ["recon"]
        if role == "recon":
            reason = "I checked recent context and prepared unique discovery work"
            response = (
                f"{reason}. Skill used: {chosen_skill}. "
                f"Executor, use these findings to run the next safe step for: {message.content}"
            )
            return "task", response, ["executor"]
        if role == "executor":
            reason = "I can execute this planned step without repeating previous work"
            response = (
                f"{reason}. Skill used: {chosen_skill}. "
                f"Reviewer, validate the execution outcome for: {message.content}"
            )
            return "info", response, ["reviewer", "memory"]
        if role == "reviewer":
            reason = "I validated the plan against recent context"
            response = (
                f"{reason}. Skill used: {chosen_skill}. "
                "Feedback: keep scope tight, avoid duplicate actions, and confirm each result."
            )
            return "feedback", response, ["planner", "memory"]
        if role == "memory":
            reason = "I checked long-term notes to avoid repetition"
            response = (
                f"{reason}. Skill used: {chosen_skill}. "
                f"Linked this update to context {message.context_id} for future turns."
            )
            return "info", response, ["planner"]

        return None


class CommunicationOrchestrator:
    """Turn-based orchestrator that routes messages and enforces one speaker each turn."""

    def __init__(self, agents: Iterable[CommunicatingAgent], bus: Optional[MessageBus] = None):
        self.agents: Dict[str, CommunicatingAgent] = {agent.name: agent for agent in agents}
        self.bus = bus or MessageBus()
        self.turn_id = 0
        self._turn_locked = False
        self._planned_contexts: Set[str] = set()
        self._work_registry: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
        self.priority_by_intent = {
            "task": ["Planner", "Recon", "Executor", "Reviewer", "Memory"],
            "question": ["Planner", "Reviewer", "Memory", "Recon", "Executor"],
            "feedback": ["Reviewer", "Planner", "Memory", "Executor", "Recon"],
            "info": ["Memory", "Planner", "Executor", "Reviewer", "Recon"],
        }

    @staticmethod
    def _signature(content: str) -> str:
        return " ".join(content.lower().split())

    def _is_duplicate_work(self, sender: str, content: str, context_id: str) -> bool:
        signature = self._signature(content)
        return signature in self._work_registry[context_id][sender]

    def _register_work(self, sender: str, content: str, context_id: str):
        self._work_registry[context_id][sender].add(self._signature(content))

    def _mark_plan_if_needed(self, sender: str, intent: str, context_id: str):
        if sender == "Planner" and intent == "task":
            self._planned_contexts.add(context_id)

    def send(self, sender: str, receivers: List[str], intent: str, content: str, context_id: str) -> AgentMessage:
        self.turn_id += 1
        normalized_intent = intent.lower().strip()
        if normalized_intent not in VALID_INTENTS:
            normalized_intent = "info"

        clean_content = content.strip()
        self._mark_plan_if_needed(sender, normalized_intent, context_id)
        if sender in self.agents and self._is_duplicate_work(sender, clean_content, context_id):
            clean_content = f"{clean_content} (new angle requested to avoid repetition)"
        if sender in self.agents:
            self._register_work(sender, clean_content, context_id)

        message = AgentMessage(
            sender=sender,
            receivers=receivers,
            intent=normalized_intent,
            content=clean_content,
            timestamp=datetime.now(),
            context_id=context_id,
            turn_id=self.turn_id,
        )
        self.bus.publish(message)
        return message

    def _eligible_receivers(self, message: AgentMessage) -> List[CommunicatingAgent]:
        receivers: List[CommunicatingAgent] = []
        for agent in self.agents.values():
            if agent.can_receive(message):
                receivers.append(agent)
                agent.remember(message)
        return receivers

    def pick_next_speaker(self, message: AgentMessage, candidates: Optional[List[CommunicatingAgent]] = None) -> Optional[CommunicatingAgent]:
        selected_candidates = candidates if candidates is not None else self._eligible_receivers(message)
        if not selected_candidates:
            return None

        # Planning-first rule: before any work, Planner must speak first.
        if message.context_id not in self._planned_contexts:
            planner = self.agents.get("Planner")
            if planner and planner in selected_candidates and planner.name != message.sender:
                return planner

        ordered_names = self.priority_by_intent.get(message.intent, list(self.agents.keys()))
        for name in ordered_names:
            for candidate in selected_candidates:
                if candidate.name == name and candidate.name != message.sender:
                    return candidate

        for candidate in selected_candidates:
            if candidate.name != message.sender:
                return candidate

        return None

    def process_next_turn(self) -> Optional[AgentMessage]:
        if self._turn_locked or not self.bus.has_messages():
            return None

        self._turn_locked = True
        try:
            incoming = self.bus.pop()
            candidates = self._eligible_receivers(incoming)
            speaker = self.pick_next_speaker(incoming, candidates=candidates)
            if not speaker:
                return None

            result = speaker.generate_response(incoming)
            if not result:
                return None

            intent, content, receivers = result
            outgoing = self.send(speaker.name, receivers, intent, content, incoming.context_id)
            self._print_cli_line(speaker, outgoing)
            return outgoing
        finally:
            self._turn_locked = False

    def run_session(self, user_prompt: str, context_id: str = "session-1", max_turns: int = 10):
        self.send("User", ["planner"], "task", user_prompt, context_id)

        turns = 0
        idle_streak = 0
        while turns < max_turns and self.bus.has_messages():
            output = self.process_next_turn()
            turns += 1

            if output is None:
                idle_streak += 1
            else:
                idle_streak = 0

            # Deadlock recovery: nudge Planner after repeated idle turns while queue still has work.
            if idle_streak >= 2 and self.bus.has_messages():
                self.send(
                    "System",
                    ["planner"],
                    "info",
                    "Conversation stalled. Re-plan with different task split so agents avoid repeating work.",
                    context_id,
                )
                idle_streak = 0

    @staticmethod
    def _print_cli_line(agent: CommunicatingAgent, message: AgentMessage):
        print(f"[{message.timestamp.strftime('%H:%M:%S')}] <{agent.name}> {agent.profile.emoji}: {message.content}")


def build_default_agent_team() -> List[CommunicatingAgent]:
    """Factory for a practical starter team aligned with CortexSec workflow."""

    profiles = [
        RoleProfile("planner", "🧭", ("Break goals into tasks", "Route tasks"), skills_for_role("planner")),
        RoleProfile(
            "recon",
            "🛰️",
            ("Gather context", "Share discovery"),
            skills_for_role("recon"),
        ),
        RoleProfile(
            "executor",
            "⚙️",
            ("Execute concrete steps", "Report progress"),
            skills_for_role("executor"),
        ),
        RoleProfile(
            "reviewer",
            "✅",
            ("Quality checks", "Give feedback"),
            skills_for_role("reviewer"),
        ),
        RoleProfile(
            "memory",
            "🧠",
            ("Persist context", "Prevent repetition"),
            skills_for_role("memory"),
        ),
    ]

    return [
        CommunicatingAgent("Planner", profiles[0]),
        CommunicatingAgent("Recon", profiles[1]),
        CommunicatingAgent("Executor", profiles[2]),
        CommunicatingAgent("Reviewer", profiles[3]),
        CommunicatingAgent("Memory", profiles[4]),
    ]
