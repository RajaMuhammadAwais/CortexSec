from cortexsec.llm.openai import OpenAILLM
from cortexsec.llm.anthropic import AnthropicLLM
from cortexsec.llm.gemini import GeminiLLM


def create_llm(provider: str, model: str = "", api_key: str = None):
    provider = (provider or "openai").lower()

    if provider == "openai":
        return OpenAILLM(model=model or "gpt-4o", api_key=api_key)
    if provider == "claude":
        return AnthropicLLM(model=model or "claude-3-5-sonnet-20241022", api_key=api_key)
    if provider == "gemini":
        return GeminiLLM(model=model or "gemini-1.5-pro", api_key=api_key)

    raise ValueError(f"Unsupported provider: {provider}")
