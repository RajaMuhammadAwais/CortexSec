"""
Enhanced Terminal Executor for Agents.

Allows agents to execute terminal commands when needed to solve problems,
gather additional information, or perform advanced security testing.
"""

from __future__ import annotations

import os
import platform
import shlex
import subprocess
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from cortexsec.core.autonomy import CommandExecutor, SafetyGate, ExecutorOutput
from cortexsec.core.agent import PentestContext


class TerminalExecutorMixin:
    """
    Mixin for agents that need terminal execution capabilities.
    
    Provides safe, LLM-powered terminal command execution with:
    - Automatic safety checks
    - Command suggestion based on problem
    - Output parsing and analysis
    - Learning from command results
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executor = CommandExecutor(timeout_seconds=30)
        self.command_history: List[Dict[str, Any]] = []
    
    def execute_terminal_command(
        self,
        context: PentestContext,
        command: str,
        purpose: str = "solve problem"
    ) -> ExecutorOutput:
        """
        Execute a terminal command safely with full provenance tracking.
        
        Args:
            context: Current pentest context
            command: Command to execute
            purpose: Human-readable purpose for the command
            
        Returns:
            ExecutorOutput with command results
        """
        self.log(f"Executing terminal command: {command}")
        self.log(f"Purpose: {purpose}")
        
        # Execute with safety checks
        result = self.executor.run(context, command)
        
        # Track in history
        self.command_history.append({
            "command": command,
            "purpose": purpose,
            "exit_code": result.exit_code,
            "success": result.exit_code == 0,
            "timestamp": result.timestamp_utc
        })
        
        # Log result
        if result.exit_code == 0:
            self.log(f"✓ Command succeeded: {command}")
        else:
            self.log(f"✗ Command failed (exit {result.exit_code}): {command}")
            if result.stderr:
                self.log(f"Error: {result.stderr[:200]}")
        
        return result
    
    def suggest_terminal_command(
        self,
        problem_description: str,
        context: PentestContext
    ) -> Optional[str]:
        """
        Use LLM to suggest a terminal command to solve a problem.
        
        Args:
            problem_description: Description of the problem to solve
            context: Current pentest context for environment info
            
        Returns:
            Suggested command or None if LLM can't help
        """
        system_prompt = """You are a security testing expert who suggests safe terminal commands.
        
CRITICAL RULES:
1. NEVER suggest destructive commands (rm, mkfs, dd, shutdown, reboot)
2. Commands must be READ-ONLY and non-destructive
3. Use only standard security testing tools
4. Return ONLY the command, no explanation
5. If no safe command exists, return "NONE"

Platform: """ + platform.system() + """
Available tools: nmap, curl, wget, nc, dig, nslookup, whois, ping, traceroute, netstat
"""
        
        prompt = f"""Problem: {problem_description}

Target: {context.target}
Mode: {context.mode}

Suggest ONE safe, non-destructive terminal command to solve this problem.
Return only the command, nothing else."""

        try:
            response = self.llm.generate_text(prompt, system_prompt=system_prompt)
            command = response.strip()
            
            if command == "NONE" or not command:
                return None
            
            # Safety check the suggested command
            if not SafetyGate.evaluate(context, command)["allowed"]:
                self.log(f"LLM suggested unsafe command, blocked: {command}")
                return None
            
            return command
        except Exception as e:
            self.log(f"Error getting command suggestion: {e}")
            return None
    
    def execute_with_llm_fallback(
        self,
        context: PentestContext,
        primary_command: str,
        purpose: str
    ) -> ExecutorOutput:
        """
        Execute a command, and if it fails, ask LLM for alternative.
        
        Args:
            context: Pentest context
            primary_command: First command to try
            purpose: What we're trying to accomplish
            
        Returns:
            ExecutorOutput from successful command or final attempt
        """
        result = self.execute_terminal_command(context, primary_command, purpose)
        
        if result.exit_code != 0:
            self.log("Primary command failed, asking LLM for alternative...")
            
            problem = f"{purpose}. Tried: {primary_command}, got error: {result.stderr[:100]}"
            alternative = self.suggest_terminal_command(problem, context)
            
            if alternative and alternative != primary_command:
                self.log(f"LLM suggested alternative: {alternative}")
                result = self.execute_terminal_command(context, alternative, purpose)
        
        return result
    
    def run_security_tool(
        self,
        context: PentestContext,
        tool_name: str,
        target_override: Optional[str] = None,
        additional_flags: str = ""
    ) -> ExecutorOutput:
        """
        Run a common security testing tool with safe defaults.
        
        Args:
            context: Pentest context
            tool_name: Tool name (nmap, curl, dig, etc.)
            target_override: Optional target (defaults to context.target)
            additional_flags: Additional command-line flags
            
        Returns:
            ExecutorOutput with tool results
        """
        target = target_override or self._extract_host_from_url(context.target)
        
        # Safe tool configurations
        tool_commands = {
            "nmap": f"nmap -sV -sC --open {additional_flags} {target}",
            "curl": f"curl -I -L {additional_flags} {context.target}",
            "dig": f"dig {additional_flags} {target}",
            "whois": f"whois {additional_flags} {target}",
            "nslookup": f"nslookup {additional_flags} {target}",
            "ping": f"ping -c 4 {additional_flags} {target}",
        }
        
        if tool_name not in tool_commands:
            self.log(f"Unknown tool: {tool_name}")
            return ExecutorOutput(
                command="",
                exit_code=127,
                stdout="",
                stderr=f"Tool {tool_name} not configured",
                duration_ms=0,
                timestamp_utc=datetime.now(timezone.utc).isoformat()
            )
        
        command = tool_commands[tool_name]
        return self.execute_terminal_command(
            context,
            command,
            purpose=f"Run {tool_name} on {target}"
        )
    
    def _extract_host_from_url(self, url: str) -> str:
        """Extract hostname from URL."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc or parsed.path
    
    def analyze_command_output(self, result: ExecutorOutput) -> Dict[str, Any]:
        """
        Use LLM to analyze command output and extract security insights.
        
        Args:
            result: Command execution result
            
        Returns:
            Dictionary with analysis insights
        """
        if not result.stdout and not result.stderr:
            return {"insights": [], "findings": []}
        
        prompt = f"""Analyze this security tool output and extract key insights:

Command: {result.command}
Exit Code: {result.exit_code}

Output:
{result.stdout[:2000]}

Error (if any):
{result.stderr[:500]}

Extract:
1. Security findings (open ports, vulnerabilities, misconfigurations)
2. Interesting patterns
3. Recommendations

Return as JSON: {{"insights": [...], "findings": [...], "recommendations": [...]}}"""

        try:
            analysis = self.llm.generate_json(
                prompt,
                system_prompt="You are a security analysis expert. Extract actionable security insights from tool outputs."
            )
            return analysis
        except Exception as e:
            self.log(f"Error analyzing output: {e}")
            return {"insights": [], "findings": []}


class EnhancedSafetyGate(SafetyGate):
    """
    Enhanced safety gate with whitelist approach and environment awareness.
    """
    
    @staticmethod
    def evaluate(context: PentestContext, command: str) -> Dict[str, Any]:
        """Enhanced safety check with more granular rules."""
        
        # Call base safety check first
        base_result = SafetyGate.evaluate(context, command)
        if not base_result["allowed"]:
            return base_result
        
        cmd_lower = command.lower()
        
        # Additional destructive patterns
        dangerous_patterns = [
            "format", "del /f", "deltree", "fdisk",
            "> /dev/sda", "dd if", "chmod 777",
            "chmod -R 777", "chown -R", "kill -9 1"
        ]
        
        for pattern in dangerous_patterns:
            if pattern in cmd_lower:
                return {
                    "allowed": False,
                    "reason": f"dangerous-pattern-detected: {pattern}"
                }
        
        # Check for common safe tools (whitelist approach)
        safe_tool_prefixes = [
            "nmap", "curl", "wget", "dig", "nslookup",
            "whois", "ping", "traceroute", "host",
            "nc -zv", "telnet", "openssl s_client",
            "nikto", "sqlmap --batch", "wpscan",
            "git clone", "python", "pip install",
            "ls", "cat", "head", "tail", "grep",
            "find", "which", "echo"
        ]
        
        is_safe_tool = any(cmd_lower.startswith(prefix) for prefix in safe_tool_prefixes)
        
        if not is_safe_tool:
            return {
                "allowed": False,
                "reason": "command-not-in-safelist",
                "help": f"Command '{command}' not recognized as safe. Use standard security tools."
            }
        
        return {"allowed": True, "reason": "ok", "safety": "enhanced-check-passed"}
