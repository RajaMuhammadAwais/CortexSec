"""
Deep Thinking Agent - ReAct Pattern Implementation

This agent takes every step with deep reasoning:
1. THINK - Deep analysis of the situation
2. PLAN - Create multi-step execution plan
3. EXECUTE - Write and run scripts via terminal
4. REFLECT - Analyze results and adapt

Based on ReAct (Reasoning + Acting) research pattern.
"""

from __future__ import annotations

import os
import textwrap
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

from cortexsec.core.agent import BaseAgent, PentestContext, Finding
from cortexsec.core.terminal_executor import TerminalExecutorMixin


@dataclass
class ThoughtProcess:
    """Structured thought process for reasoning."""
    situation_analysis: str
    problem_identified: str
    hypothesis: str
    confidence: float
    reasoning_chain: List[str]


@dataclass
class ExecutionPlan:
    """Multi-step execution plan."""
    goal: str
    steps: List[Dict[str, str]]
    expected_outcome: str
    fallback_strategy: str


class DeepThinkingAgent(TerminalExecutorMixin, BaseAgent):
    """
    Advanced agent that thinks deeply before every action.
    
    Workflow:
    1. THINK - Analyze situation deeply using LLM
    2. PLAN - Create detailed multi-step plan
    3. EXECUTE - Write scripts and run them
    4. REFLECT - Learn from results
    5. REPEAT - Iterate until goal achieved
    
    Capabilities:
    - Deep reasoning about security problems
    - Multi-step plan generation
    - Script writing (Python, Bash)
    - Script execution via terminal
    - Self-reflection and learning
    """
    
    def __init__(self, llm):
        super().__init__("DeepThinkingAgent", llm)
        self.name = "DeepThinkingAgent"
        self.thoughts: List[ThoughtProcess] = []
        self.plans: List[ExecutionPlan] = []
        self.scripts_created: List[str] = []
        self.max_iterations = 5
        self.workspace_dir = "reports/agent_workspace"
    
    def run(self, context: PentestContext) -> PentestContext:
        """
        Main execution loop with deep thinking.
        
        For each iteration:
        - Think deeply about the situation
        - Create a detailed plan
        - Execute the plan (writing scripts if needed)
        - Reflect on results
        - Decide next action
        """
        self.log("=" * 60)
        self.log("🧠 DEEP THINKING AGENT ACTIVATED")
        self.log("=" * 60)
        
        # Create workspace
        os.makedirs(self.workspace_dir, exist_ok=True)
        
        for iteration in range(self.max_iterations):
            self.log(f"\n{'='*60}")
            self.log(f"🔄 ITERATION {iteration + 1}/{self.max_iterations}")
            self.log(f"{'='*60}\n")
            
            # STEP 1: THINK
            thought = self._deep_think(context, iteration)
            self.thoughts.append(thought)
            
            if thought.confidence < 0.3:
                self.log("⚠️ Low confidence - gathering more information...")
                continue
            
            # STEP 2: PLAN
            plan = self._create_execution_plan(context, thought)
            self.plans.append(plan)
            
            # STEP 3: EXECUTE
            results = self._execute_plan(context, plan)
            
            # STEP 4: REFLECT
            reflection = self._reflect_on_results(context, plan, results)
            
            # Update context with findings
            if reflection.get("findings"):
                for finding_data in reflection["findings"]:
                    context.findings.append(Finding(**finding_data))
            
            # STEP 5: DECIDE
            should_continue = self._should_continue(context, reflection)
            
            if not should_continue:
                self.log("\n✅ Goal achieved or stopping condition met")
                break
        
        # Final summary
        self._log_final_summary(context)
        
        context.history.append({
            "agent": self.name,
            "message": "Deep thinking agent completed",
            "iterations": len(self.thoughts),
            "plans_created": len(self.plans),
            "scripts_written": len(self.scripts_created),
            "findings_discovered": len([f for f in context.findings if "DeepThinking" in str(f.evidence)])
        })
        
        return context
    
    def _deep_think(self, context: PentestContext, iteration: int) -> ThoughtProcess:
        """
        STEP 1: Deep reasoning about the current situation.
        
        Uses LLM to:
        - Analyze current state
        - Identify security problems
        - Generate hypothesis
        - Provide reasoning chain
        """
        self.log("\n🤔 THINKING DEEPLY...")
        
        prompt = f"""You are a security expert analyzing a pentest assessment.

TARGET: {context.target}
ITERATION: {iteration + 1}

CURRENT STATE:
- Known findings: {len(context.findings)}
- Recon data available: {len(context.recon_data.get('raw', {}))} items
- Previous attempts: {len(self.command_history)}

PREVIOUS THOUGHTS:
{self._format_previous_thoughts()}

TASK: Analyze the situation deeply and provide structured reasoning.

Consider:
1. What security problems might exist based on the target?
2. What have we learned so far?
3. What should we investigate next?
4. What's the most promising attack vector?
5. How confident are you in this hypothesis?

Return JSON:
{{
    "situation_analysis": "Current state analysis",
    "problem_identified": "Specific security problem to investigate",
    "hypothesis": "Testable security hypothesis",
    "confidence": 0.0-1.0,
    "reasoning_chain": ["reason 1", "reason 2", ...]
}}"""

        try:
            response = self.llm.generate_json(
                prompt,
                system_prompt="You are a deep-thinking security expert. Provide thorough reasoning."
            )
            
            thought = ThoughtProcess(
                situation_analysis=response.get("situation_analysis", "Unknown"),
                problem_identified=response.get("problem_identified", "General recon"),
                hypothesis=response.get("hypothesis", "Target may have vulnerabilities"),
                confidence=float(response.get("confidence", 0.5)),
                reasoning_chain=response.get("reasoning_chain", [])
            )
            
            # Log the thought process
            self.log(f"\n📊 SITUATION ANALYSIS:")
            self.log(f"  {thought.situation_analysis}")
            self.log(f"\n❓ PROBLEM IDENTIFIED:")
            self.log(f"  {thought.problem_identified}")
            self.log(f"\n💡 HYPOTHESIS:")
            self.log(f"  {thought.hypothesis}")
            self.log(f"\n📈 CONFIDENCE: {thought.confidence:.1%}")
            self.log(f"\n🔗 REASONING CHAIN:")
            for i, reason in enumerate(thought.reasoning_chain, 1):
                self.log(f"  {i}. {reason}")
            
            return thought
            
        except Exception as e:
            self.log(f"Error in deep thinking: {e}")
            return ThoughtProcess(
                situation_analysis=f"Error occurred: {e}",
                problem_identified="Gather basic information",
                hypothesis="Target exists and is reachable",
                confidence=0.4,
                reasoning_chain=["Fallback to basic reconnaissance"]
            )
    
    def _create_execution_plan(self, context: PentestContext, thought: ThoughtProcess) -> ExecutionPlan:
        """
        STEP 2: Create a detailed multi-step plan.
        
        Uses LLM to generate:
        - Step-by-step actions
        - Expected outcomes
        - Fallback strategies
        """
        self.log("\n📋 CREATING EXECUTION PLAN...")
        
        prompt = f"""Based on this hypothesis, create a detailed execution plan.

HYPOTHESIS: {thought.hypothesis}
PROBLEM: {thought.problem_identified}
CONFIDENCE: {thought.confidence}

TARGET: {context.target}
MODE: {context.mode}

Create a 3-5 step plan to test this hypothesis safely.

Each step should:
- Use safe, non-destructive methods
- Build on previous steps
- Be executable via terminal or script

Return JSON:
{{
    "goal": "What we're trying to achieve",
    "steps": [
        {{"action": "Step 1 description", "method": "terminal/script", "command_or_script": "..."}},
        {{"action": "Step 2 description", "method": "terminal/script", "command_or_script": "..."}}
    ],
    "expected_outcome": "What we expect to find",
    "fallback_strategy": "What to do if plan fails"
}}"""

        try:
            response = self.llm.generate_json(
                prompt,
                system_prompt="You are a security testing expert. Create safe, executable plans."
            )
            
            plan = ExecutionPlan(
                goal=response.get("goal", "Test hypothesis"),
                steps=response.get("steps", []),
                expected_outcome=response.get("expected_outcome", "Unknown"),
                fallback_strategy=response.get("fallback_strategy", "Try alternative approach")
            )
            
            self.log(f"\n🎯 GOAL: {plan.goal}")
            self.log(f"\n📝 EXECUTION STEPS:")
            for i, step in enumerate(plan.steps, 1):
                self.log(f"  {i}. {step.get('action', 'Unknown step')}")
                self.log(f"     Method: {step.get('method', 'unknown')}")
            self.log(f"\n🎬 EXPECTED OUTCOME: {plan.expected_outcome}")
            
            return plan
            
        except Exception as e:
            self.log(f"Error creating plan: {e}")
            return ExecutionPlan(
                goal="Gather basic information",
                steps=[{"action": "Basic reconnaissance", "method": "terminal", "command_or_script": "curl -I " + context.target}],
                expected_outcome="HTTP headers",
                fallback_strategy="Manual inspection"
            )
    
    def _execute_plan(self, context: PentestContext, plan: ExecutionPlan) -> List[Dict[str, Any]]:
        """
        STEP 3: Execute the plan step by step.
        
        For each step:
        - If method is 'terminal', execute command directly
        - If method is 'script', write script to file and execute
        - Collect results
        """
        self.log("\n⚙️ EXECUTING PLAN...")
        
        results = []
        
        for i, step in enumerate(plan.steps, 1):
            self.log(f"\n▶️ Executing Step {i}: {step.get('action', 'Unknown')}")
            
            method = step.get("method", "terminal")
            command_or_script = step.get("command_or_script", "")
            
            if method == "script":
                # Write script to file and execute
                result = self._write_and_execute_script(
                    context,
                    command_or_script,
                    f"step_{i}_{method}.py" if "python" in command_or_script.lower() else f"step_{i}.sh"
                )
            else:
                # Direct terminal execution
                result = self.execute_terminal_command(
                    context,
                    command_or_script,
                    purpose=step.get("action", "Execute step")
                )
            
            results.append({
                "step": i,
                "action": step.get("action"),
                "method": method,
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "success": result.exit_code == 0
            })
            
            if result.exit_code == 0:
                self.log(f"  ✅ Step {i} succeeded")
            else:
                self.log(f"  ❌ Step {i} failed (exit code: {result.exit_code})")
                self.log(f"  Error: {result.stderr[:200]}")
        
        return results
    
    def _write_and_execute_script(
        self,
        context: PentestContext,
        script_content: str,
        filename: str
    ) -> Any:
        """
        Write a script to file and execute it.
        
        Args:
            context: Pentest context
            script_content: Script code
            filename: Name of script file
            
        Returns:
            ExecutorOutput from script execution
        """
        script_path = os.path.join(self.workspace_dir, filename)
        
        self.log(f"  📝 Writing script: {script_path}")
        
        try:
            # Write script to file
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            self.scripts_created.append(script_path)
            
            # Make executable if bash script
            if filename.endswith('.sh'):
                os.chmod(script_path, 0o755)
            
            # Execute based on type
            if filename.endswith('.py'):
                command = f"python {script_path}"
            elif filename.endswith('.sh'):
                command = f"bash {script_path}"
            else:
                command = script_path
            
            self.log(f"  ▶️ Executing: {command}")
            
            result = self.execute_terminal_command(
                context,
                command,
                purpose=f"Execute script {filename}"
            )
            
            return result
            
        except Exception as e:
            self.log(f"  ❌ Error writing/executing script: {e}")
            from cortexsec.core.autonomy import ExecutorOutput
            from datetime import datetime, timezone
            return ExecutorOutput(
                command=f"write script {filename}",
                exit_code=1,
                stdout="",
                stderr=str(e),
                duration_ms=0,
                timestamp_utc=datetime.now(timezone.utc).isoformat()
            )
    
    def _reflect_on_results(
        self,
        context: PentestContext,
        plan: ExecutionPlan,
        results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        STEP 4: Reflect on execution results using LLM.
        
        Analyzes:
        - Did we achieve our goal?
        - What did we learn?
        - Any security findings?
        - What should we do next?
        """
        self.log("\n🔍 REFLECTING ON RESULTS...")
        
        prompt = f"""Analyze the results of our security testing plan.

GOAL: {plan.goal}
EXPECTED OUTCOME: {plan.expected_outcome}

RESULTS:
{self._format_results(results)}

Analyze:
1. Did we achieve our goal?
2. What security insights did we gain?
3. Any vulnerabilities discovered?
4. What should we investigate next?

Return JSON:
{{
    "goal_achieved": true/false,
    "insights": ["insight 1", "insight 2"],
    "findings": [
        {{
            "title": "Finding title",
            "description": "Description",
            "severity": "Critical/High/Medium/Low",
            "confidence": 0.0-1.0,
            "evidence": "Evidence"
        }}
    ],
    "next_actions": ["action 1", "action 2"]
}}"""

        try:
            reflection = self.llm.generate_json(
                prompt,
                system_prompt="You are a security analyst reflecting on test results."
            )
            
            self.log(f"\n✅ GOAL ACHIEVED: {reflection.get('goal_achieved', False)}")
            self.log(f"\n💡 INSIGHTS:")
            for insight in reflection.get("insights", []):
                self.log(f"  • {insight}")
            
            if reflection.get("findings"):
                self.log(f"\n🚨 FINDINGS DISCOVERED: {len(reflection['findings'])}")
            
            return reflection
            
        except Exception as e:
            self.log(f"Error in reflection: {e}")
            return {
                "goal_achieved": False,
                "insights": ["Error in reflection"],
                "findings": [],
                "next_actions": ["Continue with fallback strategy"]
            }
    
    def _should_continue(self, context: PentestContext, reflection: Dict[str, Any]) -> bool:
        """Decide if we should continue iterating."""
        
        # Stop if goal achieved with high confidence
        if reflection.get("goal_achieved") and len(reflection.get("findings", [])) > 0:
            return False
        
        # Stop if no more actions suggested
        if not reflection.get("next_actions"):
            return False
        
        # Otherwise continue
        return True
    
    def _format_previous_thoughts(self) -> str:
        """Format previous thoughts for context."""
        if not self.thoughts:
            return "None yet"
        
        return "\n".join([
            f"- {t.hypothesis} (confidence: {t.confidence:.0%})"
            for t in self.thoughts[-3:]  # Last 3 only
        ])
    
    def _format_results(self, results: List[Dict[str, Any]]) -> str:
        """Format execution results for LLM."""
        formatted = []
        for r in results:
            formatted.append(f"""
Step {r['step']}: {r['action']}
  Success: {r['success']}
  Output: {r['stdout'][:200] if r['stdout'] else 'None'}
  Error: {r['stderr'][:200] if r['stderr'] else 'None'}
""")
        return "\n".join(formatted)
    
    def _log_final_summary(self, context: PentestContext):
        """Log final summary of agent work."""
        self.log("\n" + "=" * 60)
        self.log("📊 DEEP THINKING AGENT SUMMARY")
        self.log("=" * 60)
        self.log(f"Iterations completed: {len(self.thoughts)}")
        self.log(f"Plans created: {len(self.plans)}")
        self.log(f"Scripts written: {len(self.scripts_created)}")
        self.log(f"Commands executed: {len(self.command_history)}")
        self.log(f"Findings discovered: {len([f for f in context.findings if 'DeepThinking' in str(f.evidence)])}")
        
        if self.scripts_created:
            self.log(f"\n📝 Scripts created:")
            for script in self.scripts_created:
                self.log(f"  • {script}")
        
        self.log("=" * 60)
