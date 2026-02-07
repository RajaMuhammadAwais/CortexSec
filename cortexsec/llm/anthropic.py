import os
import anthropic
from cortexsec.llm.base import BaseLLM


class AnthropicLLM(BaseLLM):
    def __init__(self, model: str = "claude-3-5-sonnet-20241022", api_key: str = None):
        self.client = anthropic.Anthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY"))
        self.model = model

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=2000,
            system=system_prompt or "",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        parts = []
        for item in response.content:
            if hasattr(item, "text"):
                parts.append(item.text)
        return "\n".join(parts)
