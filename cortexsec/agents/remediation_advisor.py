"""
Automated Remediation Advisor.

Provides actionable remediation guidance:
- Auto-generates security patches
- Creates IaC (Infrastructure as Code) fixes
- Generates configuration updates
- Provides code snippets for common fixes
- Prioritizes remediation based on risk

Written with clear, human-readable logic.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from collections import defaultdict

from cortexsec.core.agent import BaseAgent, Finding, PentestContext


class RemediationAdvisor(BaseAgent):
    """
    Automated remediation advisor.
    
    Human logic: Finding bugs is only half the job. We need to FIX them.
    This agent figures out HOW to fix each vulnerability.
    """

    def __init__(self, llm):
        super().__init__("RemediationAdvisor", llm)

    def _group_findings_by_type(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """
        Group similar findings together.
        
        Human logic: If we have 10 XSS bugs, we don't need 10 separate fixes.
        Group them so we can fix them all at once.
        """
        grouped = defaultdict(list)
        
        for finding in findings:
            # Group by vulnerability type
            # Extract type from title (e.g., "SQL Injection in login" -> "SQL Injection")
            finding_type = finding.title.split(" in ")[0].strip()
            # Also group by severity
            key = f"{finding.severity}_{finding_type}"
            grouped[key].append(finding)
        
        return dict(grouped)

    def _prioritize_remediation(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """
        Figure out what to fix first.
        
        Human logic: Fix the worst problems first.
        - Critical > High > Medium > Low
        - But also consider: How many instances? How hard to exploit?
        """
        priorities = []
        
        for finding in findings:
            # Calculate priority score
            # Higher = more urgent to fix
            severity_scores = {
                "Critical": 10,
                "High": 7,
                "Medium": 4,
                "Low": 2
            }
            
            base_score = severity_scores.get(finding.severity, 1)
            
            # Increase priority if confidence is high
            confidence_boost = finding.confidence * 3
            
            # Increase priority if CVSS score is high
            cvss_boost = (finding.cvss_score / 10) * 2 if finding.cvss_score else 0
            
            total_priority = base_score + confidence_boost + cvss_boost
            
            priorities.append({
                "finding": finding,
                "priority_score": round(total_priority, 2),
                "reasoning": f"Severity: {finding.severity}, Confidence: {finding.confidence}, CVSS: {finding.cvss_score}"
            })
        
        # Sort by priority (highest first)
        return sorted(priorities, key=lambda x: x["priority_score"], reverse=True)

    def _generate_code_fixes(self, finding: Finding) -> Optional[str]:
        """
        Generate actual code to fix the vulnerability.
        
        Human logic: Don't just say "fix XSS" - SHOW them the code!
        """
        # Common fix patterns
        fix_templates = {
            "XSS": """
# Fix for XSS vulnerability
# BEFORE (vulnerable):
# output = f"<div>{user_input}</div>"

# AFTER (secure):
from html import escape
output = f"<div>{escape(user_input)}</div>"

# Or in templates:
# {{ user_input | escape }}
""",
            "SQL Injection": """
# Fix for SQL Injection
# BEFORE (vulnerable):
# query = f"SELECT * FROM users WHERE id = {user_id}"

# AFTER (secure - use parameterized queries):
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))

# Or with ORM:
# User.objects.filter(id=user_id)  # Django
# session.query(User).filter(User.id == user_id)  # SQLAlchemy
""",
            "CSRF": """
# Fix for CSRF vulnerability
# Add CSRF token to forms:

# In Django:
{% csrf_token %}

# In Flask:
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# In Express.js:
const csrf = require('csurf');
app.use(csrf());
""",
            "Missing Secure Flag": """
# Fix for cookie security
# BEFORE:
# response.set_cookie('session', value)

# AFTER:
response.set_cookie(
    'session',
    value,
    secure=True,       # Only send over HTTPS
    httponly=True,     # No JavaScript access
    samesite='Strict'  # CSRF protection
)
"""
        }
        
        # Try to match finding to a template
        for vuln_type, fix_code in fix_templates.items():
            if vuln_type.lower() in finding.title.lower():
                return fix_code
        
        return None

    def _generate_infrastructure_fixes(self, finding: Finding) -> Optional[str]:
        """
        Generate Infrastructure as Code (IaC) fixes.
        
        Human logic: Some vulnerabilities are in configuration, not code.
        Show them how to fix their servers/cloud setup.
        """
        iac_templates = {}
        
        # nginx security headers
        if "header" in finding.title.lower() or "http" in finding.title.lower():
            iac_templates["nginx"] = """
# nginx configuration for security headers
location / {
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'" always;
}
"""
        
        # TLS/SSL configuration
        if "tls" in finding.title.lower() or "ssl" in finding.title.lower() or "https" in finding.title.lower():
            iac_templates["tls"] = """
# nginx TLS configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
"""
        
        if iac_templates:
            return "\n\n".join(iac_templates.values())
        
        return None

    def _create_remediation_plan(self, context: PentestContext) -> Dict[str, Any]:
        """
        Create a complete, step-by-step remediation plan.
        
        Human logic: Give them a checklist they can follow.
        """
        # Group and prioritize findings
        grouped = self._group_findings_by_type(context.findings)
        prioritized = self._prioritize_remediation(context.findings)
        
        plan = {
            "summary": {
                "total_findings": len(context.findings),
                "critical": len([f for f in context.findings if f.severity == "Critical"]),
                "high": len([f for f in context.findings if f.severity == "High"]),
                "medium": len([f for f in context.findings if f.severity == "Medium"]),
                "low": len([f for f in context.findings if f.severity == "Low"])
            },
            "priority_order": [],
            "quick_wins": [],
            "long_term_fixes": []
        }
        
        # Create priority list
        for item in prioritized[:10]:  # Top 10
            finding = item["finding"]
            
            remediation_item = {
                "priority": item["priority_score"],
                "finding": finding.title,
                "severity": finding.severity,
                "fix_summary": finding.mitigation,
                "code_fix": self._generate_code_fixes(finding),
                "infrastructure_fix": self._generate_infrastructure_fixes(finding)
            }
            
            plan["priority_order"].append(remediation_item)
            
            # Categorize
            if finding.severity in ["Critical", "High"] and finding.confidence > 0.7:
                plan["quick_wins"].append(remediation_item)
            else:
                plan["long_term_fixes"].append(remediation_item)
        
        return plan

    def _use_llm_for_custom_fixes(self, finding: Finding) -> str:
        """
        Use AI to generate custom remediation for complex issues.
        
        Human logic: Some bugs are unique. Ask AI to write a custom fix.
        """
        fix_prompt = f"""
        You are a senior security engineer. Generate a detailed remediation guide for this vulnerability.
        
        VULNERABILITY:
        Title: {finding.title}
        Description: {finding.description}
        Severity: {finding.severity}
        Evidence: {finding.evidence[:500]}
        
        Provide:
        1. Root cause analysis (why this vulnerability exists)
        2. Step-by-step fix instructions
        3. Code examples (if applicable)
        4. Configuration changes (if applicable)
        5. Testing steps to verify the fix
        6. Prevention tips to avoid this in the future
        
        Return JSON:
        {{
            "root_cause": "explanation",
            "fix_steps": ["step 1", "step 2", ...],
            "code_example": "code snippet",
            "config_changes": "configuration",
            "testing_steps": ["test 1", "test 2", ...],
            "prevention": "how to avoid this"
        }}
        """
        
        try:
            response = self.llm.generate_json(fix_prompt)
            
            # Format as readable remediation guide
            guide = f"""
## Root Cause
{response.get('root_cause', 'Unknown')}

## Fix Steps
{chr(10).join(f"{i+1}. {step}" for i, step in enumerate(response.get('fix_steps', [])))}

## Code Example
```
{response.get('code_example', 'No code example available')}
```

## Configuration Changes
{response.get('config_changes', 'No configuration changes needed')}

## Testing Steps
{chr(10).join(f"- {step}" for step in response.get('testing_steps', []))}

## Prevention
{response.get('prevention', 'Follow security best practices')}
"""
            return guide
            
        except Exception as e:
            self.log(f"LLM fix generation failed: {e}")
            return "AI-generated fix unavailable. Please review vulnerability manually."

    def run(self, context: PentestContext) -> PentestContext:
        """
        Generate automated remediation guidance.
        
        Human logic: Help them fix everything we found, step by step.
        """
        self.log("Creating automated remediation plan...")
        
        if not context.findings:
            self.log("No findings to remediate")
            context.history.append({
                "agent": self.name,
                "message": "No vulnerabilities found to remediate"
            })
            return context
        
        # Create comprehensive remediation plan
        self.log("Prioritizing remediations...")
        plan = self._create_remediation_plan(context)
        
        # Generate detailed fixes for top issues
        self.log("Generating detailed fix guides...")
        detailed_fixes = []
        
        for item in plan["priority_order"][:5]:  # Top 5
            # Find the original finding
            finding = next((f for f in context.findings if f.title == item["finding"]), None)
            if finding:
                custom_fix = self._use_llm_for_custom_fixes(finding)
                detailed_fixes.append({
                    "finding": finding.title,
                    "detailed_guide": custom_fix
                })
        
        # Store remediation plan in context
        context.history.append({
            "agent": self.name,
            "message": "Automated remediation plan created",
            " summary": plan["summary"],
            "quick_wins_count": len(plan["quick_wins"]),
            "long_term_fixes_count": len(plan["long_term_fixes"]),
            "detailed_fixes_generated": len(detailed_fixes)
        })
        
        # Add remediation plan to context for report
        context.remediation_plan.update({
            "full_plan": plan,
            "detailed_fixes": detailed_fixes,
            "generated_at": "assessment_completion"
        })
        
        self.log(f"Remediation advisor complete. Created plan for {len(context.findings)} findings.")
        return context
