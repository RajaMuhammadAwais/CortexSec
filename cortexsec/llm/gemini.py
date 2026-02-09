import os

from cortexsec.llm.base import BaseLLM


class GeminiLLM(BaseLLM):
    """Google GenAI SDK-backed Gemini client."""

    def __init__(self, model: str = "gemini-1.5-pro", api_key: str = None):
        from google import genai

        self.model_name = model
        self.client = genai.Client(api_key=api_key or os.getenv("GOOGLE_API_KEY"))

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        response = self.client.models.generate_content(model=self.model_name, contents=full_prompt)
        return (getattr(response, "text", None) or "").strip()
