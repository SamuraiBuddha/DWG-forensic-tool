"""
DWG Forensic Tool - LLM Mode Manager

Manages LLM operating modes (AUTO, FORCE, OFF) with graceful fallback.
Coordinates health checking and configuration for LLM features.
"""

import logging
import os
from enum import Enum
from typing import Dict, Any, Optional

from dwg_forensic.llm.ollama_health import OllamaHealthChecker

logger = logging.getLogger(__name__)


class LLMMode(Enum):
    """
    LLM operating modes.

    AUTO: Enable LLM if Ollama is available (default, graceful fallback)
    FORCE: Require LLM (fail if Ollama unavailable)
    OFF: Disable LLM regardless of availability
    """

    AUTO = "auto"
    FORCE = "force"
    OFF = "off"

    @classmethod
    def from_string(cls, mode_str: str) -> "LLMMode":
        """
        Parse LLM mode from string.

        Args:
            mode_str: Mode string ('auto', 'force', 'off')

        Returns:
            LLMMode enum value

        Raises:
            ValueError: If mode string is invalid
        """
        mode_str = mode_str.lower().strip()
        try:
            return cls(mode_str)
        except ValueError:
            raise ValueError(
                f"Invalid LLM mode: '{mode_str}'. "
                f"Must be one of: {', '.join(m.value for m in cls)}"
            )


class LLMModeManager:
    """
    Manages LLM operating mode and configuration.

    Handles:
    - Mode selection (AUTO/FORCE/OFF)
    - Health checking for AUTO mode
    - Configuration management
    - Caching support
    """

    ENV_VAR_MODE = "LLM_MODE"
    ENV_VAR_CACHE = "LLM_CACHE_ENABLED"

    def __init__(
        self,
        mode: Optional[LLMMode] = None,
        enable_caching: bool = True,
        health_checker: Optional[OllamaHealthChecker] = None,
    ):
        """
        Initialize mode manager.

        Args:
            mode: LLM mode (default: AUTO, or from LLM_MODE env var)
            enable_caching: Enable result caching (default: True, or from env)
            health_checker: Custom health checker (default: create new)
        """
        # Load mode from env var if not specified
        if mode is None:
            mode_str = os.environ.get(self.ENV_VAR_MODE, "auto")
            try:
                mode = LLMMode.from_string(mode_str)
            except ValueError as e:
                logger.warning(f"{e}. Defaulting to AUTO mode.")
                mode = LLMMode.AUTO

        self.mode = mode
        self.enable_caching = enable_caching

        # Load cache setting from env var
        cache_env = os.environ.get(self.ENV_VAR_CACHE, "").lower()
        if cache_env in ("0", "false", "no", "off"):
            self.enable_caching = False

        # Initialize health checker
        self.health_checker = health_checker or OllamaHealthChecker()

        # Cache health check result for AUTO mode
        self._cached_availability: Optional[bool] = None

        logger.debug(
            f"LLMModeManager initialized: mode={self.mode.value}, "
            f"caching={self.enable_caching}"
        )

    def is_enabled(self) -> bool:
        """
        Check if LLM features are enabled.

        For AUTO mode: Checks Ollama availability (cached)
        For FORCE mode: Always returns True (caller must handle errors)
        For OFF mode: Always returns False

        Returns:
            True if LLM should be enabled, False otherwise
        """
        if self.mode == LLMMode.OFF:
            logger.debug("LLM disabled (OFF mode)")
            return False

        if self.mode == LLMMode.FORCE:
            logger.debug("LLM enabled (FORCE mode - assuming available)")
            return True

        # AUTO mode: check availability
        if self._cached_availability is None:
            self._cached_availability = self.health_checker.is_available()
            if self._cached_availability:
                logger.info("LLM enabled (AUTO mode - Ollama available)")
            else:
                logger.info("LLM disabled (AUTO mode - Ollama unavailable)")

        return self._cached_availability

    def get_config(self) -> Dict[str, Any]:
        """
        Get current LLM configuration.

        Returns:
            Dictionary with configuration:
            - mode: LLMMode enum value
            - llm_enabled: bool - whether LLM is enabled
            - cache_enabled: bool - whether caching is enabled
            - fallback_mode: bool - whether operating in fallback mode (AUTO + unavailable)
            - ollama_available: bool - Ollama availability (None if not checked)
        """
        ollama_available = None
        fallback_mode = False

        if self.mode == LLMMode.AUTO:
            ollama_available = self.is_enabled()
            fallback_mode = not ollama_available

        return {
            "mode": self.mode,
            "llm_enabled": self.is_enabled(),
            "cache_enabled": self.enable_caching,
            "fallback_mode": fallback_mode,
            "ollama_available": ollama_available,
        }

    def reset_cache(self) -> None:
        """
        Reset cached availability check.

        Forces re-check on next is_enabled() call.
        Useful after configuration changes or Ollama restarts.
        """
        self._cached_availability = None
        logger.debug("LLM availability cache reset")

    def get_status_report(self) -> str:
        """
        Get human-readable status report.

        Returns:
            Multi-line status report string
        """
        config = self.get_config()
        lines = [
            f"LLM Mode: {config['mode'].value.upper()}",
            f"LLM Enabled: {'Yes' if config['llm_enabled'] else 'No'}",
            f"Caching: {'Enabled' if config['cache_enabled'] else 'Disabled'}",
        ]

        if config["mode"] == LLMMode.AUTO:
            if config["ollama_available"]:
                lines.append("Status: Ollama available")
            else:
                lines.append("Status: Ollama unavailable (fallback mode)")

        return "\n".join(lines)
