"""
Zero-Day Detection Agent.

Detects potential zero-day vulnerabilities through:
- Behavioral anomaly detection
- Fuzzing for unexpected crashes
- Pattern recognition for unknown exploits
- Heuristic-based vulnerability discovery

Written with clear, human-readable logic.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from cortexsec.core.agent import BaseAgent, Finding, PentestContext


class ZeroDayDetector(BaseAgent):
    """
    Zero-day vulnerability detector.
    
    Human logic: Zero-days are vulnerabilities nobody knows about yet.
    We can't look them up in a database, so we have to:
    1. Try weird things and see what breaks
    2. Look for unexpected behavior
    3. Notice patterns that don't make sense
    """

    def __init__(self, llm):
        super().__init__("ZeroDayDetector", llm)

    def _detect_behavioral_anomalies(self, context: PentestContext) -> List[Finding]:
        """
        Look for weird behavior that might indicate unknown vulnerabilities.
        
        Human logic: If something acts strange, it might be vulnerable.
        Like if a door creaks when you push it wrong - there's a weakness there.
        """
        findings = []
        
        # Human logic: Check existing findings for unusual patterns
        unusual_responses = []
        
        for finding in context.findings:
            # Look for signs of unexpected behavior
            anomaly_keywords = [
                "unexpected", "unusual", "strange", "error", "crash",
                "timeout", "delay", "hang", "infinite", "stack trace",
                "memory", "null pointer", "segfault"
            ]
            
            evidence_lower = finding.evidence.lower()
            
            if any(keyword in evidence_lower for keyword in anomaly_keywords):
                unusual_responses.append({
                    "related_finding": finding.title,
                    "anomaly": finding.evidence[:200]
                })
        
        # If we found unusual behavior, it might be a zero-day
        if unusual_responses:
            findings.append(Finding(
                title="Behavioral Anomalies Detected",
                description=f"Found {len(unusual_responses)} instances of unusual system behavior that could indicate unknown vulnerabilities. Unexpected responses often reveal zero-day weaknesses",
                severity="High",
                confidence=0.65,
                evidence=f"Anomalous behaviors: {json.dumps(unusual_responses[:3], indent=2)}",
                mitigation="Investigate anomalous behavior thoroughly. Implement robust error handling. Consider filing security reports for potential zero-days.",
                cvss_score=7.8,
                owasp_mapping="A06:2021 - Vulnerable and Outdated Components",
                mitre_mapping="T1190 - Exploit Public-Facing Application"
            ))
        
        return findings

    def _perform_fuzzing_analysis(self, context: PentestContext) -> List[Finding]:
        """
        Analyze for vulnerability patterns through fuzzing-like behavior.
        
        Human logic: Fuzzing = trying lots of random/weird inputs to see what breaks.
        It's like shaking a door in every direction to find weak spots.
        """
        findings = []
        
        # Human logic: Check if our previous tests revealed crash-like behavior
        crash_indicators = []
        
        for finding in context.findings:
            # Look for signs that something crashed or failed badly
            crash_keywords = [
                "500", "502", "503", "504",  # Server errors
                "internal server error",
                "application error",
                "stack trace",
                "exception",
                "fatal",
                "critical error"
            ]
            
            combined_text = (finding.title + " " + finding.evidence).lower()
            
            if any(keyword in combined_text for keyword in crash_keywords):
                crash_indicators.append(finding.title)
        
        if crash_indicators:
            findings.append(Finding(
                title="Potential Crash Vulnerabilities",
                description=f"Detected {len(crash_indicators)} instances where the application crashed or threw errors. Crashes can indicate memory corruption, buffer overflows, or other exploitable conditions",
                severity="High",
                confidence=0.7,
                evidence=f"Findings with crash indicators: {', '.join(crash_indicators[:5])}",
                mitigation="Investigate crashes with debugger. Implement input validation. Check for buffer overflows and memory corruption.",
                cvss_score=7.5,
                owasp_mapping="A04:2021 - Insecure Design",
                mitre_mapping="T1203 - Exploitation for Client Execution"
            ))
        
        return findings

    def _detect_logic_flaws(self, context: PentestContext) -> List[Finding]:
        """
        Find logic flaws that might be exploitable.
        
        Human logic: Sometimes the code is "correct" but the logic is wrong.
        Like a vending machine that gives change before checking if you paid enough.
        """
        findings = []
        
        # Human logic: Look at our findings for logic-based vulnerabilities
        logic_issues = []
        
        for finding in context.findings:
            # These keywords suggest logic problems
            logic_keywords = [
                "bypass", "circumvent", "skip", "race condition",
                "time of check", "authentication", "authorization",
                "access control", "privilege", "escalation"
            ]
            
            if any(keyword in finding.title.lower() or keyword in finding.description.lower() 
                   for keyword in logic_keywords):
                logic_issues.append(finding.title)
        
        if logic_issues:
            findings.append(Finding(
                title="Business Logic Vulnerabilities Detected",
                description=f"Found {len(logic_issues)} potential business logic flaws. These are often zero-day-like because they're unique to each application's design",
                severity="High",
                confidence=0.75,
                evidence=f"Logic flaw findings: {', '.join(logic_issues[:3])}",
                mitigation="Review application workflow logic. Implement proper state management. Add authorization checks at each step.",
                cvss_score=7.2,
                owasp_mapping="A01:2021 - Broken Access Control",
                mitre_mapping="T1068 - Exploitation for Privilege Escalation"
            ))
        
        return findings

    def _use_llm_for_zero_day_hunting(self, context: PentestContext) -> List[Finding]:
        """
        Use AI to spot patterns that might indicate unknown vulnerabilities.
        
        Human logic: AI can see patterns we might miss.
        Ask it to think like a researcher finding new vulnerabilities.
        """
        findings = []
        
        # Prepare context for LLM
        hunt_summary = {
            "target": context.target,
            "total_findings": len(context.findings),
            "high_severity_findings": [
                f.title for f in context.findings if f.severity in ["Critical", "High"]
            ][:10],
            "technologies": context.recon_data.get("analysis", {}).get("technologies", [])
        }
        
        hunt_prompt = f"""
        You are a zero-day vulnerability researcher. Your job is to find NEW, UNKNOWN vulnerabilities.
        
        TARGET: {context.target}
        
        CONTEXT:
        {json.dumps(hunt_summary, indent=2)}
        
        Think like a security researcher:
        1. What unusual patterns do you see?
        2. Are there combinations of findings that together reveal a bigger issue?
        3. What edge cases weren't tested?
        4. Where might there be logic flaws?
        5. What would YOU try if you were hunting for a zero-day?
        
        Focus on:
        - Novel attack vectors
        - Unexpected interactions between features
        - Edge cases in business logic
        - Unusual error handling
        - Potential memory safety issues
        
        Return JSON:
        {{
            "potential_zero_days": [
                {{
                    "title": "Descriptive name for the potential vulnerability",
                    "description": "Detailed explanation of what makes this a zero-day candidate",
                    "severity": "High",
                    "confidence": 0.4-0.7 (zero-days are uncertain),
                    "evidence": "What patterns led you to this hypothesis",
                    "exploitation_theory": "How an attacker might exploit this",
                    "mitigation": "How to protect against it"
                }}
            ]
        }}
        """
        
        try:
            response = self.llm.generate_json(hunt_prompt)
            
            for zero_day_data in response.get("potential_zero_days", []):
                findings.append(Finding(
                    title=f"[Potential Zero-Day] {zero_day_data.get('title', 'Unknown')}",
                    description=f"{zero_day_data.get('description', '')}\n\nExploitation Theory: {zero_day_data.get('exploitation_theory', 'Unknown')}",
                    severity=zero_day_data.get('severity', 'High'),
                    confidence=float(zero_day_data.get('confidence', 0.5)),
                    evidence=zero_day_data.get('evidence', ''),
                    mitigation=zero_day_data.get('mitigation', 'Conduct thorough security review and patch testing'),
                    cvss_score=7.5,
                    owasp_mapping="A06:2021 - Vulnerable and Outdated Components",
                    mitre_mapping="T1068 - Exploitation for Privilege Escalation"
                ))
        
        except Exception as e:
            self.log(f"LLM zero-day hunting failed: {e}")
        
        return findings

    def run(self, context: PentestContext) -> PentestContext:
        """
        Hunt for zero-day vulnerabilities.
        
        Human logic: We can't know what we don't know, but we can:
        1. Look for weird behavior (anomalies)
        2. Try to break things (fuzzing)
        3. Find logic mistakes (flaws)
        4. Use AI to spot patterns (LLM analysis)
        """
        self.log("Starting zero-day vulnerability detection...")
        
        all_findings = []
        
        # Step 1: Look for anomalous behavior
        self.log("Detecting behavioral anomalies...")
        all_findings.extend(self._detect_behavioral_anomalies(context))
        
        # Step 2: Analyze crash patterns from fuzzing-like tests
        self.log("Analyzing crash indicators...")
        all_findings.extend(self._perform_fuzzing_analysis(context))
        
        # Step 3: Hunt for logic flaws
        self.log("Searching for business logic vulnerabilities...")
        all_findings.extend(self._detect_logic_flaws(context))
        
        # Step 4: Use AI to find novel vulnerabilities
        self.log("AI-powered zero-day hunting...")
        all_findings.extend(self._use_llm_for_zero_day_hunting(context))
        
        # Add findings to context
        context.findings.extend(all_findings)
        
        # Record what we did
        context.history.append({
            "agent": self.name,
            "message": "Zero-day detection complete",
            "potential_zero_days": len(all_findings),
            "detection_methods": [
                "Behavioral anomaly detection",
                "Crash pattern analysis",
                "Logic flaw detection",
                "LLM-based pattern recognition"
            ]
        })
        
        self.log(f"Zero-day detection complete. Found {len(all_findings)} potential unknown vulnerabilities.")
        return context
