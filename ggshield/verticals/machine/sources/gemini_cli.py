"""
Gemini CLI credentials source.

Scans ~/.gemini/ for API keys.
"""

import re
from pathlib import Path
from typing import Iterator, Optional

from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)
from ggshield.verticals.machine.sources.base import SecretSource


# Pattern for env file lines
ENV_LINE_PATTERN = re.compile(r"^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.+?)\s*$")


class GeminiCliSource(SecretSource):
    """Collects secrets from Gemini CLI configuration."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.GEMINI_CLI

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from Gemini CLI config.

        Checks ~/.gemini/.env for API keys.
        """
        gemini_dir = self._home_dir / ".gemini"
        if not gemini_dir.exists() or not gemini_dir.is_dir():
            return

        # Check .env file
        env_path = gemini_dir / ".env"
        if not env_path.exists() or not env_path.is_file():
            return

        try:
            content = env_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        # Keys we're looking for
        secret_keys = {
            "GEMINI_API_KEY",
            "GOOGLE_API_KEY",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "API_KEY",
        }

        for line in content.splitlines():
            match = ENV_LINE_PATTERN.match(line)
            if match:
                key, value = match.groups()
                if key in secret_keys:
                    # Remove quotes if present
                    if (value.startswith('"') and value.endswith('"')) or (
                        value.startswith("'") and value.endswith("'")
                    ):
                        value = value[1:-1]

                    if value:
                        yield GatheredSecret(
                            value=value,
                            metadata=SecretMetadata(
                                source_type=self.source_type,
                                source_path=str(env_path),
                                secret_name=key,
                            ),
                        )
