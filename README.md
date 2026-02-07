# 🧠 CortexSec - AI Autonomous Pentesting Agent

CortexSec is an autonomous multi-agent framework for penetration testing, designed for authorized security assessments. This system leverages a multi-agent architecture to plan, recon, analyze vulnerabilities, and assess exploitability without executing attacks.

## 🚀 Features

- **Multi-Agent Architecture**: Specialized agents for Recon, Vulnerability Analysis, and Reporting.
- **LLM-Agnostic**: Supports OpenAI, Claude, and Gemini (via extensible base class).
- **Lab-Safe Execution**: Built-in guards to prevent unauthorized targeting (localhost only in lab mode).
- **Professional Reporting**: Generates technical and executive reports with OWASP Top 10 and MITRE ATT&CK mapping.
- **Risk Scoring**: Automated risk assessment and remediation guidance.

## 🛠 Installation

### Prerequisites
- Python 3.8+
- LLM API Key (OpenAI, Anthropic, or Google)

### Step-by-Step Setup

1. **Clone the Repository**
   ```bash
   git clone https://github.com/RajaMuhammadAwais/Ai-pentest.git
   cd Ai-pentest
   ```

2. **Create a Virtual Environment (Recommended)**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -e .
   ```

4. **Set Up Environment Variables**
   Create a `.env` file in the root directory:
   ```env
   OPENAI_API_KEY=your_openai_api_key
   # Optional: ANTHROPIC_API_KEY=your_claude_api_key
   # Optional: GOOGLE_API_KEY=your_gemini_api_key
   ```

## 🎯 Usage

### 1. Lab Mode (Safety First)
Test the agent against a local target. Lab mode strictly enforces `localhost` or `127.0.0.1` targets.
```bash
cortexsec start --target http://localhost:8080 --mode lab
```

### 2. Authorized Assessment
Perform an assessment on an authorized external target.
```bash
cortexsec start --target https://example.com --mode authorized
```

### 3. Custom API Key
You can also provide the API key directly via the CLI:
```bash
cortexsec start --target https://example.com --mode authorized --api-key YOUR_API_KEY
```

## 📊 Reports
After the assessment completes, a professional Markdown report is generated in the `reports/` directory. The report includes:
- **Executive Summary**: High-level overview for management.
- **Detailed Findings**: Technical breakdown of identified vulnerabilities.
- **Remediation Guidance**: Actionable steps to fix issues.
- **Compliance Mapping**: OWASP Top 10 and MITRE ATT&CK context.

## ⚖️ Legal Disclaimer

**IMPORTANT:** This tool is for educational and authorized security testing purposes only. Unauthorized access to computer systems is illegal. The developers assume no liability for any misuse or damage caused by this tool. By using this software, you agree to only target systems you own or have explicit, written permission to test.
