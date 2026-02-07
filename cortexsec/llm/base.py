from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import json

class BaseLLM(ABC):
    """
    Abstract base class for LLM providers.
    """
    
    @abstractmethod
    def generate(self, prompt: str, system_prompt: str = "") -> str:
        """Generates a response from the LLM."""
        pass

    def generate_json(self, prompt: str, system_prompt: str = "") -> Dict[str, Any]:
        """Generates a structured JSON response from the LLM."""
        response = self.generate(prompt, system_prompt)
        try:
            # Basic cleaning of the response to extract JSON
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0].strip()
            elif "```" in response:
                response = response.split("```")[1].split("```")[0].strip()
            return json.loads(response)
        except Exception as e:
            return {"error": f"Failed to parse JSON: {str(e)}", "raw_response": response}
