"""Tests for Deep Thinking Agent functionality."""

import pytest
import os
from unittest.mock import Mock, patch, MagicMock

from cortexsec.agents.deep_thinking_agent import DeepThinkingAgent, ThoughtProcess, ExecutionPlan
from cortexsec.core.agent import PentestContext, Finding
from cortexsec.core.autonomy import ExecutorOutput


class MockLLM:
    def __init__(self):
        self.generate_json_count = 0
    
    def generate_json(self, prompt, system_prompt=""):
        self.generate_json_count += 1
        p_lower = prompt.lower()
        s_lower = system_prompt.lower()
        
        # Mock behavior based on prompt content or count
        if "thinking" in s_lower or "reasoning" in s_lower or "thinking" in p_lower:
            return {
                "situation_analysis": "Target has open ports",
                "problem_identified": "Potential vulnerability in service",
                "hypothesis": "Service is outdated",
                "confidence": 0.8,
                "reasoning_chain": ["Port 80 is open", "Banner says old version"]
            }
        elif "execution plan" in p_lower:
            return {
                "goal": "Verify service version",
                "steps": [
                    {"action": "Run curl", "method": "terminal", "command_or_script": "curl -I http://example.com"},
                    {"action": "Check version", "method": "script", "command_or_script": "print('vulnerable')"}
                ],
                "expected_outcome": "Banner revealed",
                "fallback_strategy": "Try nmap"
            }
        elif "analyze the results" in p_lower:
            return {
                "goal_achieved": True,
                "insights": ["Service is indeed old"],
                "findings": [
                    {
                        "title": "Outdated Service",
                        "description": "Nginx 1.0 found",
                        "severity": "High",
                        "confidence": 0.9,
                        "evidence": "DeepThinking result"
                    }
                ],
                "next_actions": []
            }
        return {}

    def generate_text(self, prompt, system_prompt=""):
        return "example command"


def base_context():
    return PentestContext(
        target="http://example.com",
        mode="authorized",
        recon_data={},
    )


def test_deep_thinking_agent_initialization():
    """Test the agent initializes correctly."""
    agent = DeepThinkingAgent(MockLLM())
    assert agent.name == "DeepThinkingAgent"
    assert agent.workspace_dir == "reports/agent_workspace"


def test_deep_think_step():
    """Test the THINK step of the agent."""
    agent = DeepThinkingAgent(MockLLM())
    context = base_context()
    thought = agent._deep_think(context, 0)
    
    assert isinstance(thought, ThoughtProcess)
    assert thought.confidence == 0.8
    assert "Port 80 is open" in thought.reasoning_chain


def test_create_plan_step():
    """Test the PLAN step of the agent."""
    agent = DeepThinkingAgent(MockLLM())
    context = base_context()
    thought = ThoughtProcess("analysis", "problem", "hypothesis", 0.8, ["reason"])
    
    plan = agent._create_execution_plan(context, thought)
    
    assert isinstance(plan, ExecutionPlan)
    assert len(plan.steps) == 2
    assert plan.goal == "Verify service version"


@patch('os.makedirs')
@patch('os.path.join')
@patch('builtins.open', new_callable=MagicMock)
def test_execute_plan_step(mock_open, mock_join, mock_makedirs):
    """Test the EXECUTE step of the agent."""
    agent = DeepThinkingAgent(MockLLM())
    context = base_context()
    
    # Mock terminal executor
    with patch.object(agent, 'execute_terminal_command') as mock_exec:
        mock_exec.return_value = ExecutorOutput(
            command="cmd", exit_code=0, stdout="out", stderr="", duration_ms=1, timestamp_utc="now"
        )
        
        plan = ExecutionPlan(
            goal="test",
            steps=[{"action": "run", "method": "terminal", "command_or_script": "echo hello"}],
            expected_outcome="hello",
            fallback_strategy="none"
        )
        
        results = agent._execute_plan(context, plan)
        
        assert len(results) == 1
        assert results[0]["success"] is True
        assert results[0]["stdout"] == "out"


def test_reflection_step():
    """Test the REFLECT step of the agent."""
    agent = DeepThinkingAgent(MockLLM())
    context = base_context()
    plan = ExecutionPlan("goal", [], "outcome", "fallback")
    results = [{"step": 1, "success": True, "stdout": "out", "stderr": "", "action": "act", "method": "term"}]
    
    reflection = agent._reflect_on_results(context, plan, results)
    
    assert reflection["goal_achieved"] is True
    assert len(reflection["findings"]) == 1
    assert reflection["findings"][0]["title"] == "Outdated Service"


def test_full_run_loop():
    """Test a full run of the agent with multiple steps."""
    agent = DeepThinkingAgent(MockLLM())
    agent.max_iterations = 1 # Keep it short for test
    context = base_context()
    
    # Mock workspace and file operations
    with patch('os.makedirs'), \
         patch('os.path.join', side_effect=lambda *args: "/".join(args)), \
         patch('builtins.open', MagicMock()), \
         patch.object(agent, 'execute_terminal_command') as mock_exec:
        
        mock_exec.return_value = ExecutorOutput(
            command="cmd", exit_code=0, stdout="out", stderr="", duration_ms=1, timestamp_utc="now"
        )
        
        result_context = agent.run(context)
        
        assert len(agent.thoughts) > 0
        assert len(agent.plans) > 0
        assert any("Outdated Service" in f.title for f in result_context.findings)


def test_negative_low_confidence():
    """Test that agent handles low confidence by continuing to think."""
    mock_llm = MockLLM()
    # Force low confidence
    mock_llm.generate_json = lambda p, s="": {
        "confidence": 0.1,
        "situation_analysis": "not sure",
        "problem_identified": "none",
        "hypothesis": "none",
        "reasoning_chain": []
    }
    
    agent = DeepThinkingAgent(mock_llm)
    agent.max_iterations = 2
    context = base_context()
    
    with patch('os.makedirs'):
        result = agent.run(context)
        # Should have iterated
        assert len(agent.thoughts) == 2


def test_negative_execution_failure():
    """Test that agent handles execution failure in reflection."""
    mock_llm = MockLLM()
    # Mock reflection to handle failure
    original_generate_json = mock_llm.generate_json
    def mock_gen_json(prompt, system_prompt=""):
        if "analyze the results" in prompt.lower():
            return {
                "goal_achieved": False,
                "insights": ["Command failed"],
                "findings": [],
                "next_actions": ["Try something else"]
            }
        return original_generate_json(prompt, system_prompt)
    
    mock_llm.generate_json = mock_gen_json
    
    agent = DeepThinkingAgent(mock_llm)
    agent.max_iterations = 1
    context = base_context()
    
    with patch('os.makedirs'), \
         patch.object(agent, 'execute_terminal_command') as mock_exec:
        
        mock_exec.return_value = ExecutorOutput(
            command="fail", exit_code=1, stdout="", stderr="error", duration_ms=1, timestamp_utc="now"
        )
        
        result = agent.run(context)
        assert len(result.findings) == 0
        assert any("Deep thinking agent completed" in h["message"] for h in result.history)
