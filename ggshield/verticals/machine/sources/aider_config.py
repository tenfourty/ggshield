"""
Aider configuration source.

Scans ~/.aider.conf.yml for API keys.
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


# Pattern for YAML key: value
YAML_KEY_PATTERN = re.compile(r"^\s*([a-z_-]+)\s*:\s*(.+?)\s*$", re.IGNORECASE)


class AiderConfigSource(SecretSource):
    """Collects secrets from Aider configuration."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.AIDER_CONFIG

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from Aider config files.

        Checks ~/.aider.conf.yml for API keys.
        """
        config_path = self._home_dir / ".aider.conf.yml"
        if not config_path.exists() or not config_path.is_file():
            return

        try:
            content = config_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        # Keys that contain secrets
        secret_keys = {
            "api-key",
            "api_key",
            "openai-api-key",
            "openai_api_key",
            "anthropic-api-key",
            "anthropic_api_key",
            "azure-api-key",
            "azure_api_key",
        }

        for line in content.splitlines():
            match = YAML_KEY_PATTERN.match(line)
            if match:
                key, value = match.groups()
                key_lower = key.lower()

                if (
                    key_lower in secret_keys
                    or "api" in key_lower
                    and "key" in key_lower
                ):
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
                                source_path=str(config_path),
                                secret_name=key,
                            ),
                        )
