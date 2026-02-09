# Deep Thinking Agent - Complete Guide

## Overview

The **Deep Thinking Agent** uses the ReAct (Reasoning + Acting) pattern to solve security problems with human-like reasoning.

### Workflow

```
1. 🤔 THINK   → Deep analysis with LLM reasoning
2. 📋 PLAN    → Create multi-step execution plan  
3. ⚙️ EXECUTE → Write scripts & run via terminal
4. 🔍 REFLECT → Analyze results with AI
5. 🔄 ADAPT   → Decide next action & iterate
```

## Key Features

✨ **Deep Reasoning** - Thinks before every action  
📝 **Script Writing** - Generates Python & Bash scripts  
🖥️ **Terminal Execution** - Runs scripts safely  
🧠 **Self-Learning** - Reflects and adapts  
📊 **Confidence Scoring** - Quantifies certainty  

## How It Works

### Step 1: THINK 🤔

Agent deeply analyzes the situation using LLM:

```
Situation Analysis:
  "Target is a web application on HTTPS. No previous findings.
   Standard web vulnerabilities likely exist."

Problem Identified:
  "Authentication mechanism unknown - potential weak points"

Hypothesis:
  "Login page may be vulnerable to SQL injection or weak credentials"

Confidence: 75%

Reasoning Chain:
  1. Web apps often have authentication
  2. Authentication is a common attack surface
  3. SQL injection is prevalent in login forms
  4. Target uses database (likely based on tech stack)
```

### Step 2: PLAN 📋

Creates detailed multi-step execution plan:

```
Goal: Test authentication for SQL injection vulnerability

Steps:
  1. Discover login endpoint (method: terminal, command: curl)
  2. Analyze login form structure (method: script, script: parse_form.py)
  3. Test SQL injection payloads (method: script, script: test_sqli.py)
  4. Verify finding (method: terminal, command: curl with proof)

Expected Outcome:
  "If vulnerable, login bypassed or error messages reveal DB structure"

Fallback Strategy:
  "If SQL injection fails, test for weak credentials or session issues"
```

### Step 3: EXECUTE ⚙️

Executes plan step-by-step:

**Example: Writing a Script**

```python
# Agent writes this to reports/agent_workspace/step_2_parse_form.py

import requests
from bs4 import BeautifulSoup

url = "https://example.com/login"
response = requests.get(url)
soup = BeautifulSoup(response.text, 'html.parser')

# Find login form
form = soup.find('form')
inputs = form.find_all('input')

print("Form fields found:")
for inp in inputs:
    print(f"  - {inp.get('name')}: {inp.get('type')}")
```

**Then executes:**
```bash
python reports/agent_workspace/step_2_parse_form.py
```

**Output:**
```
Form fields found:
  - username: text
  - password: password
  - submit: submit
```

### Step 4: REFLECT 🔍

Analyzes results with AI:

```
Goal Achieved: Partial

Insights:
  • Login form discovered with username/password fields
  • Standard form structure (no CAPTCHA or 2FA visible)
  • Form action posts to /api/login
  • No CSRF token found in form

Findings:
  - Title: "Missing CSRF Protection on Login"
    Severity: Medium
    Confidence: 0.85
    Evidence: "No CSRF token in login form HTML"

Next Actions:
  • Test SQL injection in username field
  • Test for brute force protection
  • Check session management
```

### Step 5: ADAPT 🔄

Decides whether to continue:

- ✅ If goal achieved → Stop
- ✅ If high-value findings → Stop  
- 🔄 If more to explore → Continue with next iteration

## Usage Example

```python
from cortexsec.agents.deep_thinking_agent import DeepThinkingAgent

# Initialize
agent = DeepThinkingAgent(llm)

# Run on target
context = PentestContext(
    target="https://example.com",
    mode="authorized"
)

result_context = agent.run(context)

# View findings
for finding in result_context.findings:
    print(f"Found: {finding.title}")

# View generated scripts
print(f"Scripts created: {agent.scripts_created}")
```

## Real-World Example

### Iteration 1

**THINK:**
- Hypothesis: "Web app may have API endpoints with weak authentication"
- Confidence: 70%

**PLAN:**
- Step 1: Discover API endpoints (curl /api/*)
- Step 2: Test authentication (write test_auth.py)
- Step 3: Analyze responses

**EXECUTE:**
```python
# Agent writes: test_auth.py
import requests

api_urls = [
    "https://example.com/api/users",
    "https://example.com/api/admin",
    "https://example.com/api/config"
]

for url in api_urls:
    # Test without auth
    r = requests.get(url)
    print(f"{url}: {r.status_code}")
```

**Output:**
```
https://example.com/api/users: 401 (Unauthorized)
https://example.com/api/admin: 403 (Forbidden)
https://example.com/api/config: 200 (OK!)  ← Interesting!
```

**REFLECT:**
- Finding discovered: /api/config accessible without authentication
- Severity: High
- Next: Check what config data is exposed

### Iteration 2

**THINK:**
- Hypothesis: "Config endpoint may leak sensitive data"
- Confidence: 85%

**PLAN:**
- Fetch /api/config
- Parse JSON response
- Check for secrets

**EXECUTE:**
```bash
curl https://example.com/api/config
```

**Output:**
```json
{
  "db_host": "internal-db.example.com",
  "api_key": "sk_live_abc123...",
  "debug_mode": true
}
```

**REFLECT:**
- Critical finding: API key exposed!
- Stop condition met: High-severity finding with proof

## Generated Files

All scripts are saved in `reports/agent_workspace/`:

```
reports/agent_workspace/
├── step_1_terminal.py
├── step_2_parse_form.py
├── step_3_test_sqli.py
└── step_4_verify.sh
```

## Safety Features

✅ All scripts pass through `EnhancedSafetyGate`  
✅ No destructive operations allowed  
✅ Scripts executed in isolated workspace  
✅ 30-second timeout per execution  
✅ Full audit trail maintained  

## Configuration

```python
agent = DeepThinkingAgent(llm)

# Customize
agent.max_iterations = 10  # More thinking cycles
agent.workspace_dir = "custom/path"  # Custom workspace
```

## Comparison with Standard Agents

| Feature | Standard Agent | Deep Thinking Agent |
|---------|----------------|-------------------|
| Reasoning | Basic | Deep LLM-powered |
| Planning | Single step | Multi-step plans |
| Script Writing | ❌ No | ✅ Yes |
| Self-Reflection | ❌ No | ✅ Yes |
| Adaptation | Limited | Full iteration |
| Confidence Scoring | ❌ No | ✅ Yes |

## Best Use Cases

✅ **Complex investigations** - Multi-step attack chains  
✅ **Custom tooling needed** - Standard tools insufficient  
✅ **Unknown vulnerabilities** - Requires creative testing  
✅ **Deep analysis** - Need thorough examination  

❌ **Simple scans** - Use standard agents (faster)  
❌ **Known patterns** - Use specialized agents  

## Integration

Add to orchestrator workflow:

```python
from cortexsec.agents.deep_thinking_agent import DeepThinkingAgent

agents = [
    # ... other agents ...
    DeepThinkingAgent(llm),
]
```

The agent will:
1. Think deeply about findings from other agents
2. Create investigation plans
3. Write custom scripts to test hypotheses
4. Discover complex, multi-step vulnerabilities

---

**The Deep Thinking Agent brings true autonomous problem-solving to CortexSec - it doesn't just follow rules, it reasons about security like a human expert!**
