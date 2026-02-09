# Terminal Execution Feature - Documentation

## Overview

Agents can now execute terminal commands to solve problems autonomously. This powerful feature enables agents to:

- **Run security tools** (nmap, curl, dig, whois, etc.)
- **Get LLM suggestions** for commands when standard methods fail
- **Analyze tool output** with AI-powered insights
- **Solve problems** by trying alternative approaches

## Safety First

All terminal execution goes through enhanced safety checks:

✅ **Whitelist approach** - Only approved security tools allowed  
✅ **Destructive command blocking** - rm, mkfs, dd, etc. blocked  
✅ **Mode enforcement** - Requires `authorized` mode  
✅ **Timeout protection** - Commands timeout after 30 seconds

## Usage

### 1. Basic Usage (Any Agent)

```python
from cortexsec.core.terminal_executor import TerminalExecutorMixin
from cortexsec.core.agent import BaseAgent

class MyAgent(TerminalExecutorMixin, BaseAgent):
    def __init__(self, llm):
        super().__init__(llm)
        self.name = "MyAgent"
    
    def run(self, context):
        # Execute a safe command
        result = self.execute_terminal_command(
            context,
            "nmap -sV example.com",
            purpose="Scan for open ports"
        )
        
        if result.exit_code == 0:
            print(f"Success! Output: {result.stdout}")
        
        return context
```

### 2. LLM-Powered Command Suggestion

```python
# Agent encounters a problem
problem = "Need to find DNS records for target but standard method failed"

# Ask LLM for a command
suggested_cmd = self.suggest_terminal_command(problem, context)

if suggested_cmd:
    # LLM might suggest: "dig +short example.com"
    result = self.execute_terminal_command(context, suggested_cmd, problem)
```

### 3. Automatic Fallback

```python
# Try primary command, fallback to LLM if it fails
result = self.execute_with_llm_fallback(
    context,
    primary_command="nmap -p 80,443 example.com",
    purpose="Check web ports"
)

# If nmap fails, LLM suggests alternative like: "nc -zv example.com 80 443"
```

### 4. Pre-configured Security Tools

```python
# Run common tools easily
dns_result = self.run_security_tool(context, "dig")
whois_result = self.run_security_tool(context, "whois")
curl_result = self.run_security_tool(context, "curl", additional_flags="-I")
```

### 5. AI-Powered Output Analysis

```python
result = self.run_security_tool(context, "nmap", additional_flags="-sV")

# Let AI analyze the output
analysis = self.analyze_command_output(result)

print(analysis["insights"])      # ["Port 80 open with nginx"]
print(analysis["findings"])       # ["Webserver detected"]
print(analysis["recommendations"]) # ["Check nginx version for CVEs"]
```

## Allowed Tools

**Network Scanning:**
- `nmap` - Port scanning
- `nc` (netcat) - Network connections
- `ping` - Connectivity testing
- `traceroute` - Route tracing

**DNS & Domain:**
- `dig` - DNS lookups
- `nslookup` - Name server lookup
- `whois` - Domain registration info
- `host` - DNS queries

**Web Testing:**
- `curl` - HTTP requests
- `wget` - File downloads
- `nikto` - Web scanner
- `wpscan` - WordPress scanner

**Other:**
- `openssl s_client` - TLS/SSL testing
- `sqlmap --batch` - SQL injection testing
- Standard utilities: `ls`, `cat`, `grep`, `find`

## Blocked Patterns

❌ `rm`, `del`, `format` - File deletion  
❌ `dd`, `mkfs`, `fdisk` - Disk operations  
❌ `shutdown`, `reboot` - System control  
❌ `chmod 777`, `chown -R` - Permission changes

## Examples

### Example 1: Port Scanning with Fallback
```python
def run(self, context):
    # Try nmap first
    result = self.execute_with_llm_fallback(
        context,
        "nmap -p- --open example.com",
        "Full port scan"
    )
    
    # If nmap not installed, LLM might suggest: "nc -zv example.com 1-1000"
```

### Example 2: DNS Analysis
```python
def run(self, context):
    # Run DNS lookup
    result = self.run_security_tool(context, "dig", additional_flags="+short")
    
    # Analyze with AI
    analysis = self.analyze_command_output(result)
    
    # Report findings
    for finding in analysis["findings"]:
        context.findings.append(Finding(
            title="DNS Discovery",
            description=finding,
            ...
        ))
```

### Example 3: Problem Solving
```python
def run(self, context):
    # First attempt
    result = self.execute_terminal_command(context, "nmap example.com", "scan")
    
    if result.exit_code != 0:
        # Failed! Ask LLM for solution
        problem = f"nmap failed with: {result.stderr}"
        alternative = self.suggest_terminal_command(problem, context)
        
        if alternative:
            result = self.execute_terminal_command(context, alternative, "retry")
```

## Command History

All executed commands are tracked:

```python
# View command history
for cmd in self.command_history:
    print(f"Command: {cmd['command']}")
    print(f"Success: {cmd['success']}")
    print(f"Purpose: {cmd['purpose']}")
```

## Error Handling

```python
result = self.execute_terminal_command(context, "some_command", "test")

if result.exit_code == 0:
    # Success
    output = result.stdout
elif result.exit_code == 126:
    # Blocked by safety gate
    print("Command blocked for safety")
elif result.exit_code == 124:
    # Timeout
    print("Command timed out")
elif result.exit_code == 127:
    # Command not found
    print("Tool not installed")
else:
    # Other error
    error = result.stderr
```

## Best Practices

1. **Always specify purpose** - Makes logs readable
2. **Use tool-specific methods** - `run_security_tool()` when possible
3. **Check exit codes** - Don't assume success
4. **Analyze output** - Use `analyze_command_output()` for AI insights
5. **Enable fallbacks** - Use `execute_with_llm_fallback()`

## Testing

```bash
# Run terminal executor tests
pytest tests/test_terminal_executor.py -v
```

## Security Notes

- Only works in `authorized` mode
- Commands timeout after 30 seconds
- All destructive operations blocked
- Whitelist approach - only known-safe tools allowed
- Full audit trail in command history

---

**This feature makes CortexSec agents truly autonomous - they can now solve problems and adapt strategies dynamically using terminal tools when needed!**
