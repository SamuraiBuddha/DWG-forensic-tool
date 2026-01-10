"""
DWG Forensic Tool - Ollama Client

HTTP client for communicating with local Ollama instance.
Provides text generation capabilities for forensic narrative generation.
"""

import json
import logging
from dataclasses import dataclass
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)


@dataclass
class OllamaResponse:
    """Response from Ollama generation."""

    response: str
    model: str
    total_duration: Optional[int] = None
    eval_count: Optional[int] = None
    success: bool = True
    error: Optional[str] = None


class OllamaClient:
    """
    HTTP client for Ollama API.

    Communicates with local Ollama instance for LLM inference.
    No external dependencies required - uses urllib.
    """

    DEFAULT_BASE_URL = "http://127.0.0.1:11434"
    DEFAULT_MODEL = "phi4"  # Good balance of speed and analytical quality
    TIMEOUT_SECONDS = 120  # 2 minutes for generation

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: int = TIMEOUT_SECONDS,
    ):
        """
        Initialize Ollama client.

        Args:
            base_url: Ollama API base URL (default: http://127.0.0.1:11434)
            model: Model name to use (default: llama3.2)
            timeout: Request timeout in seconds
        """
        self.base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self.model = model or self.DEFAULT_MODEL
        self.timeout = timeout

    def is_available(self) -> bool:
        """
        Check if Ollama is running and accessible.

        Returns:
            True if Ollama is responding, False otherwise
        """
        try:
            req = Request(f"{self.base_url}/api/version")
            with urlopen(req, timeout=5) as response:
                return response.status == 200
        except (URLError, HTTPError, TimeoutError):
            return False

    def get_version(self) -> Optional[str]:
        """
        Get Ollama version.

        Returns:
            Version string or None if unavailable
        """
        try:
            req = Request(f"{self.base_url}/api/version")
            with urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                return data.get("version")
        except (URLError, HTTPError, TimeoutError, json.JSONDecodeError):
            return None

    def list_models(self) -> list[str]:
        """
        List available models.

        Returns:
            List of model names
        """
        try:
            req = Request(f"{self.base_url}/api/tags")
            with urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                models = data.get("models", [])
                return [m.get("name", "") for m in models]
        except (URLError, HTTPError, TimeoutError, json.JSONDecodeError):
            return []

    def is_model_available(self, model: Optional[str] = None) -> bool:
        """
        Check if a specific model is installed.

        Args:
            model: Model name (uses default if not specified)

        Returns:
            True if model is available
        """
        model = model or self.model
        available = self.list_models()
        # Check exact match or base name match (e.g., "llama3.2" matches "llama3.2:latest")
        return any(
            m == model or m.startswith(f"{model}:") or model.startswith(f"{m.split(':')[0]}")
            for m in available
        )

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.1,  # Low temperature for factual accuracy
        max_tokens: Optional[int] = None,
    ) -> OllamaResponse:
        """
        Generate text completion.

        Args:
            prompt: User prompt with forensic data
            system_prompt: System prompt defining persona and rules
            model: Model to use (overrides default)
            temperature: Sampling temperature (0.0-1.0, lower = more deterministic)
            max_tokens: Maximum tokens to generate (None = model default)

        Returns:
            OllamaResponse with generated text
        """
        model = model or self.model

        # Build request body
        body = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }

        if system_prompt:
            body["system"] = system_prompt

        if max_tokens:
            body["options"]["num_predict"] = max_tokens

        try:
            req = Request(
                f"{self.base_url}/api/generate",
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            with urlopen(req, timeout=self.timeout) as response:
                data = json.loads(response.read().decode())

                return OllamaResponse(
                    response=data.get("response", ""),
                    model=data.get("model", model),
                    total_duration=data.get("total_duration"),
                    eval_count=data.get("eval_count"),
                    success=True,
                )

        except HTTPError as e:
            error_msg = f"HTTP error {e.code}: {e.reason}"
            logger.error(f"Ollama generation failed: {error_msg}")
            return OllamaResponse(
                response="",
                model=model,
                success=False,
                error=error_msg,
            )
        except URLError as e:
            error_msg = f"Connection error: {e.reason}"
            logger.error(f"Ollama connection failed: {error_msg}")
            return OllamaResponse(
                response="",
                model=model,
                success=False,
                error=error_msg,
            )
        except TimeoutError:
            error_msg = f"Request timed out after {self.timeout}s"
            logger.error(f"Ollama generation timed out: {error_msg}")
            return OllamaResponse(
                response="",
                model=model,
                success=False,
                error=error_msg,
            )
        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON response: {e}"
            logger.error(f"Ollama response parse failed: {error_msg}")
            return OllamaResponse(
                response="",
                model=model,
                success=False,
                error=error_msg,
            )
