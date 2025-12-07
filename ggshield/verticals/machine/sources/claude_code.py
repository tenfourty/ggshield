"""
Claude Code credentials source.

Scans ~/.claude/ for API keys and OAuth tokens.
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


class ClaudeCodeSource(SecretSource):
    """Collects secrets from Claude Code configuration."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.CLAUDE_CODE

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from Claude Code config files.

        Checks:
        - ~/.claude/credentials.json (OAuth tokens)
        - ~/.claude/claude.json (may contain API key)
        """
        claude_dir = self._home_dir / ".claude"
        if not claude_dir.exists() or not claude_dir.is_dir():
            return

        # Check credentials.json
        yield from self._gather_from_credentials(claude_dir / "credentials.json")

        # Check claude.json
        yield from self._gather_from_config(claude_dir / "claude.json")

    def _gather_from_credentials(self, creds_path: Path) -> Iterator[GatheredSecret]:
        """Extract tokens from credentials.json."""
        if not creds_path.exists() or not creds_path.is_file():
            return

        try:
            content = creds_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        try:
            creds = json.loads(content)
        except json.JSONDecodeError:
            return

        # Look for OAuth tokens
        token_fields = [
            "access_token",
            "refresh_token",
            "id_token",
            "accessToken",
            "refreshToken",
        ]
        for field in token_fields:
            value = creds.get(field)
            if value and isinstance(value, str):
                yield GatheredSecret(
                    value=value,
                    metadata=SecretMetadata(
                        source_type=self.source_type,
                        source_path=str(creds_path),
                        secret_name=field,
                    ),
                )

    def _gather_from_config(self, config_path: Path) -> Iterator[GatheredSecret]:
        """Extract API key from claude.json."""
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

        # Look for API key
        api_key_fields = ["api_key", "apiKey", "anthropic_api_key"]
        for field in api_key_fields:
            value = config.get(field)
            if value and isinstance(value, str):
                yield GatheredSecret(
                    value=value,
                    metadata=SecretMetadata(
                        source_type=self.source_type,
                        source_path=str(config_path),
                        secret_name=field,
                    ),
                )
