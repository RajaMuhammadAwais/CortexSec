"""Tests for Terminal Executor functionality."""

import pytest
from unittest.mock import Mock, patch

from cortexsec.core.terminal_executor import TerminalExecutorMixin, EnhancedSafetyGate
from cortexsec.core.agent import PentestContext, BaseAgent
from cortexsec.core.autonomy import ExecutorOutput


class MockLLM:
    def generate_text(self, prompt, system_prompt=""):
        return "nmap -sV example.com"
    
    def generate_json(self, prompt, system_prompt=""):
        return {
            "insights": ["Port 80 open", "Service: nginx"],
            "findings": ["Web server detected"],
            "recommendations": ["Check for known vulnerabilities"]
        }


class AgentForTesting(TerminalExecutorMixin, BaseAgent):
    def __init__(self, llm):
        super().__init__("AgentForTesting", llm)
        self.name = "AgentForTesting"
    
    def run(self, context):
        return context


def base_context():
    return PentestContext(
        target="https://example.com",
        mode="authorized",
        recon_data={"raw": {}, "analysis": {}},
    )


def test_terminal_executor_mixin_initialization():
    """Test that mixin initializes correctly."""
    agent = AgentForTesting(MockLLM())
    
    assert hasattr(agent, "executor")
    assert hasattr(agent, "command_history")
    assert len(agent.command_history) == 0


def test_execute_terminal_command_success():
    """Test successful command execution."""
    agent = AgentForTesting(MockLLM())
    context = base_context()
    
    with patch.object(agent.executor, 'run') as mock_run:
        mock_run.return_value = ExecutorOutput(
            command="echo test",
            exit_code=0,
            stdout="test\n",
            stderr="",
            duration_ms=10,
            timestamp_utc="2024-01-01T00:00:00Z"
        )
        
        result = agent.execute_terminal_command(context, "echo test", "test command")
        
        assert result.exit_code == 0
        assert result.stdout == "test\n"
        assert len(agent.command_history) == 1
        assert agent.command_history[0]["success"]


def test_execute_terminal_command_failure():
    """Test failed command execution."""
    agent = AgentForTesting(MockLLM())
    context = base_context()
    
    with patch.object(agent.executor, 'run') as mock_run:
        mock_run.return_value = ExecutorOutput(
            command="invalid_command",
            exit_code=127,
            stdout="",
            stderr="command not found",
            duration_ms=5,
            timestamp_utc="2024-01-01T00:00:00Z"
        )
        
        result = agent.execute_terminal_command(context, "invalid_command", "test")
        
        assert result.exit_code == 127
        assert len(agent.command_history) == 1
        assert not agent.command_history[0]["success"]


def test_suggest_terminal_command():
    """Test LLM command suggestion."""
    agent = AgentForTesting(MockLLM())
    context = base_context()
    
    command = agent.suggest_terminal_command("scan for open ports", context)
    
    assert command is not None
    assert "nmap" in command


def test_suggest_unsafe_command_blocked():
    """Test that unsafe LLM suggestions are blocked."""
    agent = AgentForTesting(MockLLM())
    agent.llm.generate_text = lambda p, s="": "rm -rf /"
    context = base_context()
    
    command = agent.suggest_terminal_command("delete everything", context)
    
    assert command is None  # Unsafe command should be blocked


def test_run_security_tool():
    """Test running a security tool."""
    agent = AgentForTesting(MockLLM())
    context = base_context()
    
    with patch.object(agent.executor, 'run') as mock_run:
        mock_run.return_value = ExecutorOutput(
            command="dig +short example.com",
            exit_code=0,
            stdout="93.184.216.34\n",
            stderr="",
            duration_ms=100,
            timestamp_utc="2024-01-01T00:00:00Z"
        )
        
        result = agent.run_security_tool(context, "dig", additional_flags="+short")
        
        assert result.exit_code == 0
        assert "93.184.216.34" in result.stdout


def test_analyze_command_output():
    """Test LLM analysis of command output."""
    agent = AgentForTesting(MockLLM())
    
    result = ExecutorOutput(
        command="nmap -sV example.com",
        exit_code=0,
        stdout="PORT STATE SERVICE\n80/tcp open http nginx",
        stderr="",
        duration_ms=5000,
        timestamp_utc="2024-01-01T00:00:00Z"
    )
    
    analysis = agent.analyze_command_output(result)
    
    assert "insights" in analysis
    assert len(analysis["insights"]) > 0


def test_enhanced_safety_gate_blocks_dangerous():
    """Test enhanced safety gate blocks dangerous commands."""
    context = base_context()
    
    # Should block dangerous commands
    dangerous = [
        "rm -rf /",
        "format c:",
        "dd if=/dev/zero of=/dev/sda",
        "chmod -R 777 /",
    ]
    
    for cmd in dangerous:
        result = EnhancedSafetyGate.evaluate(context, cmd)
        assert not result["allowed"], f"Should block: {cmd}"


def test_enhanced_safety_gate_allows_safe():
    """Test enhanced safety gate allows safe commands."""
    context = base_context()
    
    # Should allow safe tools
    safe = [
        "nmap -sV example.com",
        "curl -I https://example.com",
        "dig example.com",
        "whois example.com",
    ]
    
    for cmd in safe:
        result = EnhancedSafetyGate.evaluate(context, cmd)
        assert result["allowed"], f"Should allow: {cmd}"


def test_extract_host_from_url():
    """Test host extraction from various URL formats."""
    agent = AgentForTesting(MockLLM())
    
    assert agent._extract_host_from_url("https://example.com") == "example.com"
    assert agent._extract_host_from_url("http://example.com:8080") == "example.com:8080"
    assert agent._extract_host_from_url("https://sub.example.com/path") == "sub.example.com"


def test_unauthorized_mode_blocks_execution():
    """Test that non-authorized mode blocks execution."""
    agent = AgentForTesting(MockLLM())
    context = PentestContext(
        target="https://example.com",
        mode="lab",  # Not authorized
        recon_data={}
    )
    
    result = agent.execute_terminal_command(context, "nmap example.com", "test")
    
    # Should be blocked by safety gate
    assert result.exit_code == 126
    assert "blocked" in result.stderr.lower()
