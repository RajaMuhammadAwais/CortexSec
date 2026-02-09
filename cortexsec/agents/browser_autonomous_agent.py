"""
Browser-Enabled Autonomous Testing Agent.

Advanced agent with browser automation capabilities similar to Claude Bot and Moltbot:
- Visual web application interaction
- Browser-based vulnerability testing
- DOM manipulation and inspection
- JavaScript execution
- Screenshot-based analysis with vision models
- Multi-step browser workflows
- Tool-using capabilities (like Claude)
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, NoSuchElementException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

from cortexsec.agents.real_world_guidance import real_world_prompt
from cortexsec.core.agent import BaseAgent, Finding, PentestContext


@dataclass
class BrowserAction:
    """Represents an action to take in the browser."""
    
    action_type: str  # click, type, navigate, extract, screenshot, execute_js
    selector: Optional[str] = None
    value: Optional[str] = None
    reasoning: str = ""


@dataclass
class BrowserObservation:
    """Observation from browser interaction."""
    
    url: str
    title: str
    screenshot_b64: Optional[str] = None
    dom_summary: str = ""
    console_logs: List[str] = None
    network_requests: List[Dict] = None
    rendered_content: str = ""


class BrowserAutonomousAgent(BaseAgent):
    """
    Autonomous agent with browser capabilities (Claude/Moltbot-like).
    
    This agent can:
    - Navigate and interact with web applications
    - Make autonomous decisions about what to test
    - Use browser tools to find vulnerabilities
    - Analyze visual feedback and screenshots
    - Execute complex multi-step browser workflows
    """

    def __init__(self, llm, headless: bool = True, timeout: int = 10):
        super().__init__("BrowserAutonomousAgent", llm)
        self.headless = headless
        self.timeout = timeout
        self.driver = None

    def _init_browser(self):
        """Initialize Selenium browser."""
        if not SELENIUM_AVAILABLE:
            self.log("Selenium not available. Install with: pip install selenium")
            return False

        try:
            options = webdriver.ChromeOptions()
            if self.headless:
                options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            
            self.driver = webdriver.Chrome(options=options)
            self.driver.set_page_load_timeout(self.timeout)
            return True
        except Exception as e:
            self.log(f"Failed to initialize browser: {e}")
            return False

    def _close_browser(self):
        """Close browser."""
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None

    def _capture_screenshot(self) -> Optional[str]:
        """Capture screenshot as base64."""
        if not self.driver:
            return None

        try:
            screenshot = self.driver.get_screenshot_as_base64()
            return screenshot
        except Exception as e:
            self.log(f"Screenshot failed: {e}")
            return None

    def _get_dom_summary(self) -> str:
        """Get simplified DOM structure."""
        if not self.driver:
            return ""

        try:
            # Get important elements
            js_script = """
            function getDOMSummary() {
                let summary = {
                    forms: [],
                    inputs: [],
                    links: [],
                    buttons: []
                };
                
                // Forms
                document.querySelectorAll('form').forEach(form => {
                    summary.forms.push({
                        action: form.action,
                        method: form.method,
                        id: form.id
                    });
                });
                
                // Inputs
                document.querySelectorAll('input').forEach(input => {
                    summary.inputs.push({
                        type: input.type,
                        name: input.name,
                        id: input.id,
                        placeholder: input.placeholder
                    });
                });
                
                // Links
                document.querySelectorAll('a').forEach((link, i) => {
                    if (i < 20) {  // Limit to 20
                        summary.links.push({
                            href: link.href,
                            text: link.innerText.substring(0, 50)
                        });
                    }
                });
                
                // Buttons
                document.querySelectorAll('button').forEach(btn => {
                    summary.buttons.push({
                        text: btn.innerText,
                        id: btn.id,
                        type: btn.type
                    });
                });
                
                return summary;
            }
            return getDOMSummary();
            """
            
            dom_data = self.driver.execute_script(js_script)
            return json.dumps(dom_data, indent=2)
        except Exception as e:
            self.log(f"DOM summary failed: {e}")
            return ""

    def _get_console_logs(self) -> List[str]:
        """Get browser console logs."""
        if not self.driver:
            return []

        try:
            logs = self.driver.get_log('browser')
            return [log['message'] for log in logs[:20]]  # Last 20 logs
        except Exception:
            return []

    def _observe_page(self) -> BrowserObservation:
        """Capture current page state."""
        if not self.driver:
            return BrowserObservation(url="", title="", dom_summary="Browser not initialized")

        try:
            return BrowserObservation(
                url=self.driver.current_url,
                title=self.driver.title,
                screenshot_b64=self._capture_screenshot(),
                dom_summary=self._get_dom_summary(),
                console_logs=self._get_console_logs(),
                rendered_content=self.driver.page_source[:5000]  # First 5000 chars
            )
        except Exception as e:
            self.log(f"Page observation failed: {e}")
            return BrowserObservation(url="error", title="error", dom_summary=str(e))

    def _decide_next_action(self, observation: BrowserObservation, context: PentestContext) -> Optional[BrowserAction]:
        """
        Use LLM to decide next browser action (Claude-like decision-making).
        """
        decision_prompt = f"""
        You are an autonomous security testing agent with browser capabilities (like Claude or Moltbot).
        
        CURRENT PAGE STATE:
        URL: {observation.url}
        Title: {observation.title}
        
        DOM SUMMARY:
        {observation.dom_summary}
        
        Based on this page, decide what security testing action to take next.
        You can:
        - navigate: Go to a different URL
        - click: Click an element (provide CSS selector)
        - type: Type into an input field (provide selector and value)
        - extract: Extract data from page
        - screenshot: Take a screenshot for analysis
        - execute_js: Execute JavaScript for testing
        - stop: Stop testing this page
        
        Think step-by-step:
        1. What vulnerabilities might exist on this page?
        2. What should I test first?
        3. Is it safe and non-destructive?
        4. What action will give me the most information?
        
        Return JSON:
        {{
            "action_type": "click/type/navigate/extract/screenshot/execute_js/stop",
            "selector": "CSS selector (if applicable)",
            "value": "value to type or URL to navigate (if applicable)",
            "reasoning": "Why you chose this action",
            "expected_vulnerability": "What vulnerability you're testing for"
        }}
        """

        try:
            response = self.llm.generate_json(
                decision_prompt,
                system_prompt=real_world_prompt("autonomous browser-based security tester")
            )

            if response.get("action_type") == "stop":
                return None

            return BrowserAction(
                action_type=response.get("action_type", "stop"),
                selector=response.get("selector"),
                value=response.get("value"),
                reasoning=response.get("reasoning", "")
            )

        except Exception as e:
            self.log(f"Decision making failed: {e}")
            return None

    def _execute_action(self, action: BrowserAction) -> Dict[str, Any]:
        """Execute browser action and return result."""
        if not self.driver:
            return {"success": False, "error": "Browser not initialized"}

        result = {"success": False, "action": action.action_type}

        try:
            if action.action_type == "navigate":
                self.driver.get(action.value)
                result["success"] = True
                result["new_url"] = self.driver.current_url

            elif action.action_type == "click":
                element = WebDriverWait(self.driver, self.timeout).until(
                    EC.element_to_be_clickable((By.CSS_SELECTOR, action.selector))
                )
                element.click()
                result["success"] = True

            elif action.action_type == "type":
                element = WebDriverWait(self.driver, self.timeout).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, action.selector))
                )
                element.clear()
                element.send_keys(action.value)
                result["success"] = True

            elif action.action_type == "execute_js":
                js_result = self.driver.execute_script(action.value)
                result["success"] = True
                result["js_result"] = str(js_result)[:500]

            elif action.action_type == "screenshot":
                screenshot = self._capture_screenshot()
                result["success"] = screenshot is not None
                result["screenshot"] = screenshot

            elif action.action_type == "extract":
                # Extract specific data
                elements = self.driver.find_elements(By.CSS_SELECTOR, action.selector)
                result["extracted"] = [elem.text[:100] for elem in elements[:10]]
                result["success"] = True

        except TimeoutException:
            result["error"] = "Element not found or timeout"
        except Exception as e:
            result["error"] = str(e)

        return result

    def _analyze_for_vulnerabilities(self, observation: BrowserObservation, actions_taken: List[BrowserAction]) -> List[Finding]:
        """
        Use LLM to analyze observations for vulnerabilities.
        """
        analysis_prompt = f"""
        Analyze this browser-based security testing session for vulnerabilities.
        
        PAGE: {observation.url}
        
        DOM SUMMARY:
        {observation.dom_summary}
        
        CONSOLE LOGS:
        {json.dumps(observation.console_logs, indent=2)}
        
        ACTIONS TAKEN:
        {json.dumps([{"type": a.action_type, "reasoning": a.reasoning} for a in actions_taken], indent=2)}
        
        Based on the page structure, console logs, and test results, identify potential vulnerabilities.
        
        Return JSON:
        {{
            "findings": [
                {{
                    "title": "Vulnerability title",
                    "description": "Detailed description",
                    "severity": "Critical/High/Medium/Low",
                    "confidence": 0.0-1.0,
                    "evidence": "What you observed",
                    "mitigation": "How to fix"
                }}
            ]
        }}
        """

        try:
            response = self.llm.generate_json(analysis_prompt)
            findings = []

            for finding_data in response.get("findings", []):
                findings.append(Finding(
                    title=f"[Browser Test] {finding_data.get('title', 'Unknown')}",
                    description=finding_data.get('description', ''),
                    severity=finding_data.get('severity', 'Medium'),
                    confidence=float(finding_data.get('confidence', 0.7)),
                    evidence=f"Browser-based testing at {observation.url}\n{finding_data.get('evidence', '')}",
                    mitigation=finding_data.get('mitigation', ''),
                    cvss_score=7.5 if finding_data.get('severity') == 'High' else 5.0,
                    owasp_mapping="A03:2021 - Injection",
                    mitre_mapping="T1190 - Exploit Public-Facing Application"
                ))

            return findings

        except Exception as e:
            self.log(f"Vulnerability analysis failed: {e}")
            return []

    def run(self, context: PentestContext) -> PentestContext:
        """
        Execute autonomous browser-based testing.
        
        Works like Claude Bot / Moltbot:
        1. Initialize browser
        2. Navigate to target
        3. Observe page state
        4. Decide next action autonomously
        5. Execute action
        6. Analyze for vulnerabilities
        7. Repeat
        """
        self.log("Starting browser-enabled autonomous testing (Claude/Moltbot-like)...")

        if not SELENIUM_AVAILABLE:
            context.history.append({
                "agent": self.name,
                "message": "Selenium not available. Install with: pip install selenium",
                "status": "skipped"
            })
            return context

        # Only test HTTP/HTTPS targets
        if not context.target.startswith(("http://", "https://")):
            self.log("Skipping browser test for non-HTTP target")
            return context

        # Initialize browser
        if not self._init_browser():
            context.history.append({
                "agent": self.name,
                "message": "Failed to initialize browser",
                "status": "failed"
            })
            return context

        try:
            # Navigate to target
            self.log(f"Navigating to {context.target}")
            self.driver.get(context.target)
            time.sleep(2)  # Let page load

            actions_taken = []
            max_actions = 10  # Prevent infinite loops

            for iteration in range(max_actions):
                self.log(f"Browser testing iteration {iteration + 1}/{max_actions}")

                # Observe current state
                observation = self._observe_page()
                self.log(f"Observing: {observation.title} at {observation.url}")

                # Decide next action
                action = self._decide_next_action(observation, context)

                if not action:
                    self.log("Agent decided to stop testing")
                    break

                self.log(f"Action: {action.action_type} - {action.reasoning}")

                # Execute action
                result = self._execute_action(action)
                actions_taken.append(action)

                if not result.get("success"):
                    self.log(f"Action failed: {result.get('error', 'Unknown error')}")
                    continue

                # Wait for page changes
                time.sleep(1)

                # Analyze for vulnerabilities periodically
                if iteration % 3 == 2 or iteration == max_actions - 1:
                    findings = self._analyze_for_vulnerabilities(observation, actions_taken)
                    context.findings.extend(findings)
                    self.log(f"Found {len(findings)} potential vulnerabilities")

            # Final observation and analysis
            final_observation = self._observe_page()
            final_findings = self._analyze_for_vulnerabilities(final_observation, actions_taken)
            context.findings.extend(final_findings)

            context.history.append({
                "agent": self.name,
                "message": "Browser-based autonomous testing complete",
                "actions_taken": len(actions_taken),
                "findings": len(final_findings),
                "final_url": final_observation.url
            })

        except Exception as e:
            self.log(f"Browser testing error: {e}")
            context.history.append({
                "agent": self.name,
                "message": f"Browser testing failed: {str(e)}",
                "status": "error"
            })

        finally:
            self._close_browser()

        self.log("Browser-enabled autonomous testing complete")
        return context
