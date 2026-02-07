import os
import google.generativeai as genai
from cortexsec.llm.base import BaseLLM


class GeminiLLM(BaseLLM):
    def __init__(self, model: str = "gemini-1.5-pro", api_key: str = None):
        genai.configure(api_key=api_key or os.getenv("GOOGLE_API_KEY"))
        self.model = genai.GenerativeModel(model)

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        response = self.model.generate_content(full_prompt)
        return response.text or ""
