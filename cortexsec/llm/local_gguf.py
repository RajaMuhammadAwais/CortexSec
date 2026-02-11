import subprocess
from typing import Optional

from cortexsec.llm.base import BaseLLM


class LocalGGUFLLM(BaseLLM):
    """Wrapper for llama.cpp compatible local GGUF inference."""

    def __init__(self, model_path: str, cli_path: str = "llama-cli", n_predict: int = 256):
        self.model_path = model_path
        self.cli_path = cli_path
        self.n_predict = n_predict

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        proc = subprocess.run(
            [
                self.cli_path,
                "-m",
                self.model_path,
                "-p",
                full_prompt,
                "-n",
                str(self.n_predict),
                "--no-display-prompt",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"local-gguf-inference-failed: {proc.stderr.strip()}")
        return proc.stdout.strip()
