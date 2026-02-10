from datetime import datetime

from cortexsec.core.agent_communication import (
    AgentMessage,
    CommunicationOrchestrator,
    CommunicatingAgent,
    MessageBus,
    RoleProfile,
    build_default_agent_team,
)
from cortexsec.core.agent_skills import SKILL_CATALOG, validate_unique_role_skills


def _fast_team():
    team = build_default_agent_team()
    for agent in team:
        agent.delay_range = (0.0, 0.0)
    return team


def test_planning_happens_first_before_other_agents_work():
    orchestrator = CommunicationOrchestrator(_fast_team(), bus=MessageBus())

    orchestrator.send("User", ["all"], "task", "start security assessment", "ctx-plan-first")
    first = orchestrator.process_next_turn()

    assert first is not None
    assert first.sender == "Planner"


def test_planner_is_forced_first_even_if_not_initial_receiver():
    orchestrator = CommunicationOrchestrator(_fast_team(), bus=MessageBus())

    orchestrator.send("User", ["recon"], "task", "start security assessment", "ctx-force-planner")
    first = orchestrator.process_next_turn()

    assert first is not None
    assert first.sender == "Planner"


def test_message_bus_and_orchestrator_turn_flow():
    orchestrator = CommunicationOrchestrator(_fast_team(), bus=MessageBus())

    orchestrator.send(
        sender="User",
        receivers=["planner"],
        intent="task",
        content="Map attack surface and report next step",
        context_id="ctx-1",
    )

    first = orchestrator.process_next_turn()
    second = orchestrator.process_next_turn()

    assert first is not None
    assert second is not None
    assert first.sender == "Planner"
    assert second.sender == "Recon"
    assert first.context_id == "ctx-1"
    assert first.turn_id < second.turn_id


def test_each_agent_gets_different_work_chain():
    orchestrator = CommunicationOrchestrator(_fast_team(), bus=MessageBus())
    orchestrator.send("User", ["planner"], "task", "Assess localhost app", "ctx-chain")

    planner_msg = orchestrator.process_next_turn()
    recon_msg = orchestrator.process_next_turn()
    executor_msg = orchestrator.process_next_turn()

    assert planner_msg is not None and planner_msg.sender == "Planner"
    assert recon_msg is not None and recon_msg.sender == "Recon"
    assert executor_msg is not None and executor_msg.sender == "Executor"

    assert "Recon first" in planner_msg.content
    assert "Executor" in recon_msg.content
    assert "Reviewer" in executor_msg.content


def test_duplicate_work_is_rewritten_with_new_angle():
    orchestrator = CommunicationOrchestrator(_fast_team(), bus=MessageBus())

    first = orchestrator.send("Planner", ["recon"], "task", "collect ports", "ctx-dup")
    second = orchestrator.send("Planner", ["recon"], "task", "collect ports", "ctx-dup")

    assert "new angle requested" not in first.content
    assert "new angle requested" in second.content


def test_all_receivers_store_memory_for_same_context():
    team = _fast_team()
    orchestrator = CommunicationOrchestrator(team, bus=MessageBus())

    orchestrator.send("User", ["all"], "info", "Shared update", "ctx-broadcast")
    orchestrator.process_next_turn()

    for agent in team:
        assert "ctx-broadcast" in agent.long_term_memory
        assert len(agent.long_term_memory["ctx-broadcast"]) >= 1


def test_invalid_intent_falls_back_to_info_and_question_inference_works():
    team = _fast_team()
    planner = next(agent for agent in team if agent.name == "Planner")
    orchestrator = CommunicationOrchestrator(team, bus=MessageBus())

    message = orchestrator.send("User", ["planner"], "unknown", "How should we begin?", "ctx-q")

    assert message.intent == "info"
    assert planner.infer_intent(message) == "question"


def test_turn_lock_prevents_parallel_processing():
    orchestrator = CommunicationOrchestrator(_fast_team(), bus=MessageBus())
    orchestrator.send("User", ["planner"], "task", "start", "ctx-lock")

    orchestrator._turn_locked = True
    blocked = orchestrator.process_next_turn()
    orchestrator._turn_locked = False
    allowed = orchestrator.process_next_turn()

    assert blocked is None
    assert allowed is not None


def test_can_receive_by_name_role_and_all():
    planner = CommunicatingAgent(
        "Planner",
        RoleProfile("planner", "🧭", ("Plan",), ("Threat Modeling",)),
        delay_range=(0.0, 0.0),
    )

    msg_by_name = AgentMessage("User", ["Planner"], "task", "run", datetime.now(), "ctx", 1)
    msg_by_role = AgentMessage("User", ["planner"], "task", "run", datetime.now(), "ctx", 2)
    msg_all = AgentMessage("User", ["all"], "info", "share", datetime.now(), "ctx", 3)

    assert planner.can_receive(msg_by_name)
    assert planner.can_receive(msg_by_role)
    assert planner.can_receive(msg_all)


def test_negative_no_matching_receivers_returns_no_turn_output():
    orchestrator = CommunicationOrchestrator(_fast_team(), bus=MessageBus())
    orchestrator.send("User", ["nonexistent"], "task", "nothing", "ctx-none")

    result = orchestrator.process_next_turn()

    assert result is None


def test_negative_self_only_message_has_no_new_speaker():
    orchestrator = CommunicationOrchestrator(_fast_team(), bus=MessageBus())
    orchestrator.send("Planner", ["Planner"], "info", "self note", "ctx-self")

    result = orchestrator.process_next_turn()

    assert result is None


def test_negative_empty_candidate_list_does_not_double_store_memory():
    team = _fast_team()
    planner = next(agent for agent in team if agent.name == "Planner")
    orchestrator = CommunicationOrchestrator(team, bus=MessageBus())

    message = orchestrator.send("User", ["planner"], "task", "single msg", "ctx-mem")
    candidates = orchestrator._eligible_receivers(message)
    assert len(candidates) == 1

    before = len(planner.long_term_memory["ctx-mem"])
    chosen = orchestrator.pick_next_speaker(message, candidates=[])
    after = len(planner.long_term_memory["ctx-mem"])

    assert chosen is None
    assert before == after


def test_deadlock_recovery_injects_system_replan_message():
    team = _fast_team()
    planner = next(agent for agent in team if agent.name == "Planner")
    orchestrator = CommunicationOrchestrator(team, bus=MessageBus())

    # No matching receivers -> repeated idle turns with queued messages.
    orchestrator.send("User", ["ghost"], "task", "unroutable", "ctx-deadlock")
    orchestrator.send("User", ["phantom"], "task", "still unroutable", "ctx-deadlock")

    orchestrator.run_session("ignored", context_id="ctx-deadlock", max_turns=4)

    system_msgs = [
        m for m in planner.long_term_memory["ctx-deadlock"] if m.sender == "System"
    ]
    assert system_msgs
    assert any("stalled" in m.content.lower() for m in system_msgs)


def test_default_team_has_skills_for_each_agent_role():
    team = build_default_agent_team()

    for agent in team:
        assert agent.profile.skills
        assert len(agent.profile.skills) >= 3


def test_each_role_has_unique_skills_across_catalog():
    validate_unique_role_skills()

    all_skills = []
    for role, skills in SKILL_CATALOG.items():
        assert skills, f"missing skills for role {role}"
        all_skills.extend(skill.name for skill in skills)

    assert len(all_skills) == len(set(all_skills))


def test_agent_response_mentions_skill_used():
    orchestrator = CommunicationOrchestrator(_fast_team(), bus=MessageBus())
    orchestrator.send("User", ["planner"], "task", "Create plan", "ctx-skills")

    response = orchestrator.process_next_turn()

    assert response is not None
    assert "Skill used:" in response.content
