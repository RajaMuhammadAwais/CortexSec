"""
Example agent demonstrating terminal execution capabilities.

This agent can use terminal commands to solve problems autonomously.
"""

from typing import Any, Dict

from cortexsec.core.agent import BaseAgent, PentestContext
from cortexsec.core.terminal_executor import TerminalExecutorMixin


class TerminalEnabledAgent(TerminalExecutorMixin, BaseAgent):
    """
    Example agent with terminal execution capabilities.
    
    Demonstrates how agents can:
    - Execute terminal commands safely
    - Get LLM suggestions for commands
    - Analyze command output
    - Solve problems autonomously
    """
    
    def __init__(self, llm):
        super().__init__("TerminalEnabledAgent", llm)
        self.name = "TerminalEnabledAgent"
    
    def run(self, context: PentestContext) -> PentestContext:
        """
        Run agent with terminal capabilities.
        
        Example workflow:
        1. Try to gather information
        2. If standard methods fail, use terminal
        3. Analyze results
        4. Report findings
        """
        self.log("Starting terminal-enabled agent...")
        
        # Example: Enhanced reconnaissance using terminal tools
        findings = []
        
        # 1. Try DNS lookup
        self.log("Running DNS reconnaissance...")
        dns_result = self.run_security_tool(context, "dig", additional_flags="+short")
        
        if dns_result.exit_code == 0:
            self.log(f"DNS result: {dns_result.stdout[:200]}")
            dns_analysis = self.analyze_command_output(dns_result)
            if dns_analysis.get("findings"):
                findings.extend(dns_analysis["findings"])
        
        # 2. Try port scanning (if needed)
        if context.mode == "authorized":
            self.log("Attempting port scan...")
            
            # Ask LLM for best approach
            problem = f"Need to scan {context.target} for open ports safely"
            suggested_cmd = self.suggest_terminal_command(problem, context)
            
            if suggested_cmd:
                self.log(f"LLM suggested: {suggested_cmd}")
                scan_result = self.execute_terminal_command(
                    context,
                    suggested_cmd,
                    "Port scanning"
                )
                
                if scan_result.exit_code == 0:
                    analysis = self.analyze_command_output(scan_result)
                    if analysis.get("insights"):
                        findings.extend(analysis["insights"])
        
        # 3. If we encountered errors, try to solve them
        failed_commands = [h for h in self.command_history if not h["success"]]
        
        if failed_commands:
            last_failed = failed_commands[-1]
            self.log(f"Last command failed: {last_failed['command']}")
            self.log("Asking LLM for solution...")
            
            problem = f"Command '{last_failed['command']}' failed. Purpose was: {last_failed['purpose']}"
            alternative = self.suggest_terminal_command(problem, context)
            
            if alternative:
                self.log(f"Trying alternative: {alternative}")
                self.execute_terminal_command(context, alternative, "Retry with alternative approach")
        
        # Store results in context
        context.history.append({
            "agent": self.name,
            "message": f"Terminal execution complete",
            "commands_executed": len(self.command_history),
            "successful_commands": len([h for h in self.command_history if h["success"]]),
            "findings_count": len(findings)
        })
        
        self.log(f"Terminal agent complete. Executed {len(self.command_history)} commands.")
        return context
