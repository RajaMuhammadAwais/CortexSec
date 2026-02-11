import os
from typing import Any

import requests

from cortexsec.llm.base import BaseLLM


class OllamaLLM(BaseLLM):
    def __init__(self, model: str = "llama3.1", host: str = "http://127.0.0.1:11434"):
        self.model = model
        self.host = os.getenv("OLLAMA_HOST", host).rstrip("/")

    @staticmethod
    def detect_server(host: str = "http://127.0.0.1:11434") -> bool:
        try:
            response = requests.get(f"{host.rstrip('/')}/api/tags", timeout=1.5)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system_prompt,
            "stream": False,
        }
        response = requests.post(f"{self.host}/api/generate", json=payload, timeout=90)
        response.raise_for_status()
        data = response.json()
        return data.get("response", "")
