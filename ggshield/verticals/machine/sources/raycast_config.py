"""
Raycast configuration source.

Scans ~/.config/raycast/ for API keys and OAuth tokens.
"""

import json
from pathlib import Path
from typing import Iterator, Optional

from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)
from ggshield.verticals.machine.sources.base import SecretSource


class RaycastConfigSource(SecretSource):
    """Collects secrets from Raycast configuration."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.RAYCAST_CONFIG

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from Raycast config files.

        Checks:
        - ~/.config/raycast/config.json (OAuth tokens, extension API keys)
        """
        config_dir = self._home_dir / ".config" / "raycast"
        if not config_dir.exists() or not config_dir.is_dir():
            return

        # Check config.json
        config_path = config_dir / "config.json"
        if config_path.exists() and config_path.is_file():
            yield from self._gather_from_config(config_path)

    def _gather_from_config(self, config_path: Path) -> Iterator[GatheredSecret]:
        """Extract tokens and API keys from config.json."""
        try:
            content = config_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        try:
            config = json.loads(content)
        except json.JSONDecodeError:
            return

        # Look for OAuth tokens at root level
        token_fields = [
            "access_token",
            "accessToken",
            "refresh_token",
            "refreshToken",
            "id_token",
            "idToken",
            "api_key",
            "apiKey",
        ]
        extracted_keys: set[str] = set()
        for field in token_fields:
            value = config.get(field)
            if value and isinstance(value, str) and len(value) > 5:
                yield GatheredSecret(
                    value=value,
                    metadata=SecretMetadata(
                        source_type=self.source_type,
                        source_path=str(config_path),
                        secret_name=field,
                    ),
                )
                extracted_keys.add(field)

        # Recursively search for tokens in nested structures
        # Pass extracted_keys to avoid duplicates at root level
        yield from self._search_nested(
            config, config_path, extracted_keys=extracted_keys
        )

    def _search_nested(
        self,
        data: dict,
        config_path: Path,
        max_depth: int = 5,
        extracted_keys: set | None = None,
    ) -> Iterator[GatheredSecret]:
        """Recursively search for token-like fields in nested structures."""
        if max_depth <= 0:
            return

        if extracted_keys is None:
            extracted_keys = set()

        secret_key_patterns = ["token", "key", "secret", "password", "credential"]

        for key, value in data.items():
            # Skip keys already extracted at root level
            if key in extracted_keys:
                continue

            key_lower = key.lower()

            # Check if this key looks like it contains a secret
            if any(pattern in key_lower for pattern in secret_key_patterns):
                if isinstance(value, str) and len(value) > 5:
                    yield GatheredSecret(
                        value=value,
                        metadata=SecretMetadata(
                            source_type=self.source_type,
                            source_path=str(config_path),
                            secret_name=key,
                        ),
                    )

            # Recurse into nested dicts (don't pass extracted_keys - only for root level)
            if isinstance(value, dict):
                yield from self._search_nested(value, config_path, max_depth - 1)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        yield from self._search_nested(item, config_path, max_depth - 1)
