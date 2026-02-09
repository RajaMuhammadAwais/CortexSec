from cortexsec.core.agent import PentestContext
from cortexsec.core.autonomy import (
    AutonomyLoop,
    CommandExecutor,
    PlannerOutput,
    SafetyGate,
)


def test_safety_gate_blocks_when_not_authorized():
    context = PentestContext(target="https://example.com", mode="lab")
    decision = SafetyGate.evaluate(context, "echo hello")
    assert decision["allowed"] is False
    assert decision["reason"] == "mode-not-authorized"


def test_command_executor_blocks_destructive_mode():
    context = PentestContext(target="https://example.com", mode="authorized", destructive_mode=True)
    result = CommandExecutor().run(context, "echo hello")
    assert result.exit_code == 126
    assert "blocked-by-policy:destructive-mode-enabled" in result.stderr


def test_autonomy_loop_records_thought_action_observation_trace():
    context = PentestContext(target="https://example.com", mode="authorized")
    plans = [
        PlannerOutput(
            hypothesis="target responds to safe command",
            objective="collect baseline",
            action="echo cortexsec",
            success_criteria="stdout contains cortexsec",
        )
    ]

    out = AutonomyLoop(max_steps=1).run(context, plans)
    assert out.history
    entry = out.history[-1]
    assert entry["agent"] == "AutonomyLoop"
    assert "Hypothesis" in entry["thought"]
    assert entry["action"]["command"] == "echo cortexsec"
    assert entry["observation"]["critic_verdict"] in {"accepted", "needs-followup"}


def test_command_executor_handles_missing_command():
    context = PentestContext(target="https://example.com", mode="authorized")
    result = CommandExecutor().run(context, "definitely-not-a-real-command")
    assert result.exit_code == 127
    assert result.stderr == "command-not-found"


def test_command_executor_handles_empty_command():
    context = PentestContext(target="https://example.com", mode="authorized")
    result = CommandExecutor().run(context, "")
    assert result.exit_code == 2
    assert result.stderr == "invalid-command:empty"
