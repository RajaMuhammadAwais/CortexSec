# CortexSec User Guide - Complete Feature Documentation

This guide provides detailed usage instructions and examples for every feature in CortexSec.

## Table of Contents
1. [Getting Started](#getting-started)
2. [Web Application Scanner](#1-web-application-scanner)
3. [Secrets & Credentials Scanner](#2-secrets--credentials-scanner)
4. [Network Traffic Analyzer](#3-network-traffic-analyzer)
5. [Browser Autonomous Agent](#4-browser-autonomous-agent)
6. [Autonomous Exploitation Agent](#5-autonomous-exploitation-agent)
7. [Zero-Day Detector](#6-zero-day-detector)
8. [Remediation Advisor](#7-remediation-advisor)
9. [Threat Intelligence Integration](#8-threat-intelligence-integration)
10. [Advanced Configuration](#advanced-configuration)

---

## Getting Started

### Basic Assessment Command
```bash
cortexsec start --target https://example.com --mode authorized
```

### With All Features
```bash
cortexsec start \
  --target https://example.com \
  --mode authorized \
  --max-cycles 10 \
  --llm-provider anthropic \
  --vuln-refinement-rounds 3
```

---

## 1. Web Application Scanner

**Automatically tests modern web vulnerabilities - no configuration needed!**

### What It Detects
- ✅ GraphQL introspection & injection
- ✅ JWT token security (weak algorithms, no signature)
- ✅ CSRF protection
- ✅ Session management flaws
- ✅ File upload vulnerabilities
- ✅ NoSQL injection
- ✅ SSRF, XXE, SSTI

### How to Use
```bash
# Runs automatically during discovery phase
cortexsec start --target https://webapp.example.com --mode authorized
```

### Example Output
```
[WebAppScannerAgent] Testing GraphQL endpoint...
[WebAppScannerAgent] ✓ Found GraphQL introspection enabled
[WebAppScannerAgent] Testing JWT security...
[WebAppScannerAgent] ⚠️ Found JWT using HS256 with weak secret
[WebAppScannerAgent] Testing file uploads...
[WebAppScannerAgent] ⚠️ File upload has no validation
```

### Real-World Example
```bash
# Scan a specific web application
cortexsec start --target https://admin.myapp.com --mode authorized

# Result: Found 3 critical issues
- GraphQL introspection enabled in production
- JWT tokens use weak signing algorithm
- CSRF tokens missing on admin actions
```

---

## 2. Secrets & Credentials Scanner

**Scans for 25+ types of exposed secrets - runs automatically!**

### What It Finds
- 🔑 AWS Access Keys & Secret Keys
- 🔑 GitHub Personal Access Tokens
- 🔑 Azure Connection Strings
- 🔑 GCP Service Account Keys
- 🔑 Database credentials (MySQL, PostgreSQL, MongoDB)
- 🔑 Private SSH/RSA keys
- 🔑 Slack/Discord webhooks
- 🔑 Stripe/PayPal API keys
- 🔑 JWT secrets
- 🔑 OAuth tokens

### How It Works
```bash
# Auto-enabled - scans all responses, headers, and source code
cortexsec start --target https://example.com --mode authorized
```

### Example Findings
```
[SecretsScanner] 🚨 CRITICAL: AWS Access Key exposed
Location: https://example.com/config.js
Pattern: AKIA... (20 characters)
Risk: Full AWS account compromise

[SecretsScanner] ⚠️ HIGH: GitHub Token found
Location: Response body - /api/user
Pattern: ghp_... 
Risk: Repository access

[SecretsScanner] ⚠️ MEDIUM: Database connection string
Location: Error message
Pattern: mongodb://user:pass@host:port/db
Risk: Database access
```

### Where It Looks
1. **HTTP Response Bodies** - JSON, HTML, JavaScript
2. **HTTP Headers** - Authorization, cookies, custom headers
3. **Source Code** - Embedded secrets in JS files
4. **Error Messages** - Stack traces with credentials
5. **Environment Files** - .env, config files

---

## 3. Network Traffic Analyzer

**Detects suspicious network patterns and attack indicators**

### What It Analyzes
- 🌐 DNS tunneling & rebinding
- 🔍 Port scanning behavior
- ⚠️ Protocol anomalies
- 📤 Data exfiltration patterns
- 🎯 Command & Control (C2) communications

### How to Use
```bash
# Included in all assessments
cortexsec start --target https://example.com --mode authorized
```

### Example Detection
```
[NetworkAnalyzer] Analyzing network patterns...

⚠️ HTTP Protocol Used (Unencrypted)
Target: http://example.com
Risk: Data transmitted in plaintext
Impact: Credentials, session tokens exposed

⚠️ Non-Standard Port Detected  
Target: https://example.com:8443
Analysis: HTTPS on non-standard port 8443
Note: Common in custom deployments, verify legitimacy

🚨 Multiple Open Ports
Discovered: 8 open ports [22, 80, 443, 3306, 5432, 6379, 8080, 9200]
Risk: Increased attack surface
Recommendation: Close unnecessary ports

⚠️ DNS Resolution to Private IP
Domain: internal.example.com → 192.168.1.100
Risk: Possible DNS rebinding vulnerability
```

### Real Scenario
```bash
# Scan cloud infrastructure
cortexsec start --target https://api.company.com --mode authorized

# Results:
- Service on port 9200 (Elasticsearch) exposed
- Database port 3306 (MySQL) accessible
- Redis cache on port 6379 without authentication
Recommendation: Implement network segmentation
```

---

## 4. Browser Autonomous Agent

**Interacts with web applications like a human using a real browser**

### Installation
```bash
# Install browser automation support
pip install selenium chromedriver-autoinstaller
```

### Capabilities
- 🌐 Navigate pages autonomously
- 🖱️ Click buttons, fill forms
- 📸 Capture screenshots
- 💻 Execute JavaScript
- 📊 Monitor console logs
- 🔍 Extract DOM data

### How to Use
```bash
# Runs automatically in discovery phase for HTTP/HTTPS targets
cortexsec start --target https://webapp.example.com --mode authorized
```

### Autonomous Workflow Example
```
1. Agent loads https://webapp.example.com/login
2. Inspects page structure:
   - Found: <input name="username">
   - Found: <input name="password">
   - Found: <button>Submit</button>
   
3. Agent decides: "Test SQL injection in login"

4. Agent fills form:
   username = "admin' OR '1'='1"
   password = "anything"
   
5. Agent clicks Submit

6. Agent captures:
   - Screenshot: login_attempt_001.png
   - Console: "SQL syntax error near '1'='1'"
   - Response: 500 Internal Server Error
   
7. Agent reports: "SQL Injection vulnerability in login form"
```

### Real Example
```bash
cortexsec start --target https://shop.example.com --mode authorized

# Agent workflow:
→ Navigate to product page
→ Click "Add to Cart"
→ Modify quantity parameter to negative value
→ Observe: Price becomes negative
→ Screenshot captured
→ Finding: Business logic flaw - negative quantities allowed
```

### Manual Override (Non-HTTP Targets)
```bash
# Browser agent only works with HTTP/HTTPS
# For other protocols, standard agents will run
cortexsec start --target ftp://example.com --mode authorized
# Output: Browser agent skipped (non-HTTP target)
```

---

## 5. Autonomous Exploitation Agent

**Self-learning agent that improves with every test**

### Key Features
- 🧠 **Hypothesis Generation** - Creates vulnerability theories
- 🎯 **Strategic Decisions** - Chooses what to test
- 📚 **Memory Persistence** - Learns from history
- 📈 **Improves Over Time** - Higher success rate

### How It Works

**First Run:**
```bash
cortexsec start --target https://api.example.com --mode authorized

# Agent creates hypothesis:
"Based on recon, /api/users endpoint might have SQL injection"

# Agent decides:
Confidence: 0.6 (medium)
Priority: High (critical endpoint)
Decision: Test SQL injection payloads

# Agent executes safe test:
GET /api/users?id=1' OR '1'='1

# Agent learns:
Result: Vulnerability confirmed
Memory updated: SQL injection success rate +1
```

**Second Run (Same target, later):**
```bash
cortexsec start --target https://api.example.com --mode authorized

# Agent remembers:
"SQL injection had 75% success rate before"
Decision: Prioritize SQL injection tests

# Result: Faster, more focused testing
```

### Memory File
```bash
# View learning data
cat reports/exploit_memory.json
```

```json
{
  "exploitation_stats": {
    "total_attempts": 89,
    "successful": 23,
    "success_rate": 0.258
  },
  "vulnerability_knowledge": {
    "SQL Injection": {
      "attempts": 25,
      "successes": 15,
      "success_rate": 0.600
    },
    "XSS": {
      "attempts": 30,
      "successes": 5,
      "success_rate": 0.167
    }
  },
  "recent_attempts": [...]
}
```

### Example Autonomous Decision
```
[AutonomousExploitationAgent] Analyzing target...
[AutonomousExploitationAgent] Generated 5 hypotheses:
  1. SQL Injection in /api/users (confidence: 0.7)
  2. XSS in search parameter (confidence: 0.5)
  3. IDOR in /api/profile/:id (confidence: 0.6)
  4. API key exposure (confidence: 0.4)
  5. Rate limiting bypass (confidence: 0.3)

[AutonomousExploitationAgent] Decision: Test hypothesis #1
  Reasoning: Highest confidence + critical impact
  
[AutonomousExploitationAgent] Learning from result...
  Outcome: Success (SQL injection confirmed)
  Memory updated: 16/26 SQL attempts successful (61.5%)
```

---

## 6. Zero-Day Detector

**Discovers unknown vulnerabilities using AI and heuristics**

### Detection Methods
1. **Behavioral Anomalies** - Unusual server responses
2. **Crash Analysis** - 500 errors, stack traces
3. **Logic Flaws** - Authentication/authorization bypasses
4. **AI Pattern Recognition** - Novel attack vectors

### How to Use
```bash
# Runs automatically after standard vulnerability scanning
cortexsec start --target https://example.com --mode authorized
```

### Example Detection
```
[ZeroDayDetector] Analyzing behavioral anomalies...

🔬 Potential Zero-Day Detected
Title: Unusual State Management Flaw
Description: Discovered privilege escalation through race condition
           in session handling. Not documented in CVE databases.
Confidence: 0.62 (medium - requires manual verification)
Evidence:
  - Repeated tests show inconsistent authorization
  - User session can access admin endpoints under specific timing
  - Stack trace reveals custom auth library, not standard framework
Exploitation Theory:
  - Race condition between session validation and role check
  - Exploit: Rapid requests in parallel can bypass authorization
Mitigation:
  - Implement mutex locks on session state
  - Add transaction-level authorization checks
```

### Real Example
```bash
cortexsec start --target https://newapp.startup.com --mode authorized

# Zero-day finding:
[ZeroDayDetector] 🔬 Novel Authentication Bypass
Method: Business logic flaw
Discovery: Reset password flow doesn't validate token ownership
Impact: Any user can reset any account's password
Confidence: 0.68
Status: Unpatched (vendor notified)
```

### Understanding Zero-Day Confidence
```
Confidence Range | Meaning
0.4 - 0.5        | Possible, needs investigation
0.5 - 0.6        | Likely vulnerability, manual testing advised
0.6 - 0.7        | High probability, reproducible behavior
0.7 +            | Confirmed (reclassified as known vulnerability)
```

**Note:** Zero-day findings always have lower confidence because they're new patterns. Always verify manually!

---

## 7. Remediation Advisor

**Automatically generates fix code and infrastructure templates**

### What It Provides
- 💻 **Code Fixes** - Drop-in code snippets
- 🏗️ **Infrastructure as Code** - nginx, Apache configs
- 📊 **Prioritization** - Risk-based ordering
- ⚡ **Quick Wins** - Easy, high-impact fixes
- 📖 **Custom Guides** - AI-generated remediation

### How to Use
```bash
# Runs automatically after assessment completes
cortexsec start --target https://example.com --mode authorized

# Check remediation plan
cat reports/remediation_plan.json
```

### Example Fixes

#### XSS Vulnerability
**Before (Vulnerable):**
```python
@app.route('/search')
def search():
    query = request.args.get('q')
    return f"<h1>Results for: {query}</h1>"
```

**After (Secure):**
```python
from html import escape

@app.route('/search')
def search():
    query = request.args.get('q')
    # CortexSec Fix: Escape user input to prevent XSS
    return f"<h1>Results for: {escape(query)}</h1>"
```

#### SQL Injection
**Before (Vulnerable):**
```python
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
```

**After (Secure):**
```python
def get_user(user_id):
    # CortexSec Fix: Use parameterized queries
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))
```

### Infrastructure Fixes

#### nginx Security Headers
```nginx
# CortexSec Remediation: Add security headers
location / {
    # Prevent clickjacking
    add_header X-Frame-Options "SAMEORIGIN" always;
    
    # Prevent MIME sniffing
    add_header X-Content-Type-Options "nosniff" always;
    
    # Enable XSS protection
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Enforce HTTPS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Content Security Policy
    add_header Content-Security-Policy "default-src 'self'" always;
}
```

#### TLS Configuration
```nginx
# CortexSec Remediation: Secure TLS settings
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
```

### Remediation Plan Structure
```json
{
  "summary": {
    "total_findings": 12,
    "critical": 2,
    "high": 4,
    "medium": 5,
    "low": 1
  },
  "quick_wins": [
    {
      "finding": "Missing CORS Headers",
      "severity": "High",
      "confidence": 0.95,
      "fix_time": "5 minutes",
      "fix": "Add CORS headers to API responses"
    }
  ],
  "priority_order": [
    {
      "rank": 1,
      "finding": "SQL Injection in /api/users",
      "severity": "Critical",
      "priority_score": 9.5,
      "code_fix": "...",
      "testing_steps": "..."
    }
  ]
}
```

---

## 8. Threat Intelligence Integration

**Enriches findings with real-world vulnerability data**

### Features
- 📚 CVE database integration
- 📊 CVSS score verification
- 🔧 Exploit availability checking
- 🌐 OSINT feed correlation (planned)

### Setup
```bash
# Optional: Get NVD API key for enhanced data
export NVD_API_KEY=your_key_here
```

### How It Works
```bash
# Automatically enriches all findings
cortexsec start --target https://example.com --mode authorized
```

### Example Enrichment
```
Original Finding:
[VulnAnalysisAgent] Found outdated Apache version 2.4.41

After Threat Intel Enrichment:
[ThreatIntelAgent] ✅ Enriched with CVE data
  - CVE-2021-44228 (Log4Shell) - CVSS 10.0
  - CVE-2021-41773 - Path Traversal - CVSS 7.5
  - CVE-2021-42013 - Path Traversal - CVSS 9.8
  
  Exploit Status: Public exploits available
  Published: 2021-10-04
  Patched Version: 2.4.51+
  
  Recommendation: URGENT - Update to Apache 2.4.54+
```

---

## Advanced Configuration

### Full Command Options
```bash
cortexsec start \
  --target URL \
  --mode {lab|authorized} \
  --llm-provider {openai|anthropic|google} \
  --max-cycles 20 \
  --vuln-refinement-rounds 3 \
  --confidence-threshold 0.8 \
  --coverage-threshold 0.75 \
  --exploitability-threshold 0.7
```

### Parameter Guide
| Parameter | Default | Description |
|-----------|---------|-------------|
| `--target` | Required | Target URL (must be HTTP/HTTPS) |
| `--mode` | `lab` | `lab` (localhost only) or `authorized` (any target) |
| `--llm-provider` | `openai` | AI provider: `openai`, `anthropic`, `google` |
| `--max-cycles` | `20` | Maximum assessment iterations |
| `--vuln-refinement-rounds` | `2` | Depth of vulnerability analysis |
| `--confidence-threshold` | `0.75` | Minimum confidence for findings (0-1) |

### Environment Variables
```bash
# Create .env file
cat > .env << EOF
# LLM API Keys (choose one or more)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_API_KEY=...

# Optional: Threat Intelligence
NVD_API_KEY=...

# Assessment defaults
DEFAULT_MODE=authorized
MAX_CYCLES=10
EOF
```

### Example Workflows

**Quick Scan (5 minutes):**
```bash
cortexsec start --target https://example.com --mode authorized --max-cycles 3
```

**Deep Scan (30 minutes):**
```bash
cortexsec start --target https://example.com --mode authorized --max-cycles 15 --vuln-refinement-rounds 3
```

**Continuous Monitoring:**
```bash
# Add to cron
0 2 * * * cd /path/to/CortexSec && cortexsec start --target https://example.com --mode authorized
```

---

## Report Locations

All outputs are saved in the `reports/` directory:

```
reports/
├── assessment_report.json      # Full findings
├── exploit_memory.json         # Agent learning data
├── remediation_plan.json       # Fix guidance
└── example-com-2024-02-09.md   # Human-readable report
```

---

## Safety & Ethics

### ⚠️ Authorization Required
```bash
# ONLY use on systems you own or have permission to test
--mode authorized  # Explicit permission required
```

### Non-Destructive Testing
- ✅ Read-only operations
- ✅ Safe test payloads
- ✅ No data modification
- ✅ Respects robots.txt

### Legal Reminder
**Unauthorized security testing is illegal. Only use CortexSec on systems you own or have explicit written permission to test.**

---

## Troubleshooting

### Browser Agent Not Working
```bash
# Install Selenium
pip install selenium chromedriver-autoinstaller

# Test
python -c "from selenium import webdriver; driver = webdriver.Chrome(); print('OK')"
```

### LLM API Errors
```bash
# Check API key
echo $OPENAI_API_KEY

# Test connection
curl https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY"
```

### No Findings
- Increase `--max-cycles` for deeper scanning
- Lower `--confidence-threshold` to see more potential issues
- Check target is accessible (curl/ping)

---

**Need Help?** 
- GitHub Issues: https://github.com/RajaMuhammadAwais/CortexSec/issues
- Read the main README: https://github.com/RajaMuhammadAwais/CortexSec

**Happy Testing! 🛡️**
