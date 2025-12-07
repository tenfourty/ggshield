"""
Continue.dev configuration source.

Scans ~/.continue/config.yaml for API keys.
"""

import json
import re
from pathlib import Path
from typing import Iterator, Optional

from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)
from ggshield.verticals.machine.sources.base import SecretSource


# Pattern for YAML key: value with apiKey
API_KEY_PATTERN = re.compile(r"^\s*apiKey\s*:\s*(.+?)\s*$", re.MULTILINE)


class ContinueConfigSource(SecretSource):
    """Collects secrets from Continue.dev configuration."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.CONTINUE_CONFIG

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from Continue config files.

        Checks:
        - ~/.continue/config.yaml (YAML format)
        - ~/.continue/config.json (deprecated JSON format)
        """
        continue_dir = self._home_dir / ".continue"
        if not continue_dir.exists() or not continue_dir.is_dir():
            return

        # Check YAML config
        yield from self._gather_from_yaml(continue_dir / "config.yaml")

        # Check JSON config (deprecated but may still exist)
        yield from self._gather_from_json(continue_dir / "config.json")

    def _gather_from_yaml(self, config_path: Path) -> Iterator[GatheredSecret]:
        """Extract API keys from YAML config."""
        if not config_path.exists() or not config_path.is_file():
            return

        try:
            content = config_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        # Find apiKey entries
        for match in API_KEY_PATTERN.finditer(content):
            value = match.group(1).strip()
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
                        secret_name="apiKey",
                    ),
                )

    def _gather_from_json(self, config_path: Path) -> Iterator[GatheredSecret]:
        """Extract API keys from JSON config."""
        if not config_path.exists() or not config_path.is_file():
            return

        try:
            content = config_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        try:
            config = json.loads(content)
        except json.JSONDecodeError:
            return

        # Recursively find apiKey fields
        yield from self._extract_api_keys(config, config_path)

    def _extract_api_keys(
        self, data, config_path: Path, prefix: str = ""
    ) -> Iterator[GatheredSecret]:
        """Recursively extract apiKey values from nested structure."""
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}/{key}" if prefix else key

                if key.lower() == "apikey" and isinstance(value, str) and value:
                    yield GatheredSecret(
                        value=value,
                        metadata=SecretMetadata(
                            source_type=self.source_type,
                            source_path=str(config_path),
                            secret_name=full_key,
                        ),
                    )
                elif isinstance(value, (dict, list)):
                    yield from self._extract_api_keys(value, config_path, full_key)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                yield from self._extract_api_keys(item, config_path, f"{prefix}[{i}]")
