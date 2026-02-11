from cortexsec.llm.openai import OpenAILLM
from cortexsec.llm.anthropic import AnthropicLLM
from cortexsec.llm.gemini import GeminiLLM
from cortexsec.llm.deepseek import DeepSeekLLM
from cortexsec.llm.ollama import OllamaLLM
from cortexsec.llm.local_gguf import LocalGGUFLLM


def create_llm(provider: str, model: str = "", api_key: str = None, model_path: str = ""):

    provider = (provider or "openai").lower()

    if provider == "openai":
        return OpenAILLM(model=model or "gpt-4o", api_key=api_key)
    if provider == "claude":
        return AnthropicLLM(model=model or "claude-3-5-sonnet-20241022", api_key=api_key)
    if provider == "gemini":
        return GeminiLLM(model=model or "gemini-1.5-pro", api_key=api_key)
    if provider == "deepseek":
        return DeepSeekLLM(model=model or "deepseek-reasoner", api_key=api_key)
    if provider == "ollama":
        if not OllamaLLM.detect_server():
            raise ValueError("Ollama server not detected on http://127.0.0.1:11434")
        return OllamaLLM(model=model or "llama3.1")
    if provider in {"local-gguf", "gguf"}:
        if not model_path:
            raise ValueError("model_path is required for local GGUF provider")
        return LocalGGUFLLM(model_path=model_path)

    raise ValueError(f"Unsupported provider: {provider}")
