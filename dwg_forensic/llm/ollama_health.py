"""
DWG Forensic Tool - Ollama Health Checker

Provides health checking functionality for Ollama server availability.
Used by mode manager to determine if LLM features should be enabled.
"""

import logging
from typing import Dict, Any, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import json

logger = logging.getLogger(__name__)


class OllamaHealthChecker:
    """
    Health checker for Ollama server.

    Provides quick health checks to determine if Ollama is available
    before attempting LLM operations.
    """

    DEFAULT_BASE_URL = "http://127.0.0.1:11434"
    DEFAULT_TIMEOUT = 2  # seconds

    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        """
        Initialize health checker.

        Args:
            base_url: Ollama API base URL (default: http://127.0.0.1:11434)
            timeout: Request timeout in seconds (default: 2)
        """
        self.base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout

    def is_available(self) -> bool:
        """
        Check if Ollama is running and accessible.

        Performs a quick HTTP ping to the Ollama API. Returns False on any
        error (connection refused, timeout, etc.) without raising exceptions.

        Returns:
            True if Ollama is responding, False otherwise
        """
        try:
            req = Request(f"{self.base_url}/api/version")
            with urlopen(req, timeout=self.timeout) as response:
                return response.status == 200
        except (URLError, HTTPError, TimeoutError, OSError) as e:
            logger.debug(f"Ollama health check failed: {e}")
            return False
        except Exception as e:
            # Catch any unexpected errors
            logger.warning(f"Unexpected error during Ollama health check: {e}")
            return False

    def get_status(self) -> Dict[str, Any]:
        """
        Get detailed Ollama server status.

        Returns server information including version and available models.
        Returns error information if server is unavailable.

        Returns:
            Dictionary with status information:
            - available: bool - server reachability
            - version: str - Ollama version (if available)
            - models: list[str] - available model names (if available)
            - error: str - error message (if unavailable)
        """
        status: Dict[str, Any] = {
            "available": False,
            "version": None,
            "models": [],
            "error": None,
        }

        # Check availability
        if not self.is_available():
            status["error"] = "Ollama server not responding"
            return status

        status["available"] = True

        # Get version
        try:
            req = Request(f"{self.base_url}/api/version")
            with urlopen(req, timeout=self.timeout) as response:
                data = json.loads(response.read().decode())
                status["version"] = data.get("version", "unknown")
        except (URLError, HTTPError, TimeoutError, json.JSONDecodeError) as e:
            logger.debug(f"Failed to get Ollama version: {e}")

        # Get models
        try:
            req = Request(f"{self.base_url}/api/tags")
            with urlopen(req, timeout=self.timeout) as response:
                data = json.loads(response.read().decode())
                models = data.get("models", [])
                status["models"] = [m.get("name", "") for m in models]
        except (URLError, HTTPError, TimeoutError, json.JSONDecodeError) as e:
            logger.debug(f"Failed to list Ollama models: {e}")

        return status
