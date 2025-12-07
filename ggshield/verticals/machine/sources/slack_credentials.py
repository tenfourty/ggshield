"""
Slack credentials source.

Scans ~/.slack/credentials.json for API tokens.
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


class SlackCredentialsSource(SecretSource):
    """Collects secrets from Slack credentials file."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.SLACK_CREDENTIALS

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from Slack credentials file.

        The file may contain tokens in various formats.
        """
        creds_path = self._home_dir / ".slack" / "credentials.json"
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

        # Handle different credential structures
        yield from self._extract_tokens(creds, creds_path)

    def _extract_tokens(
        self, data: dict, creds_path: Path, prefix: str = ""
    ) -> Iterator[GatheredSecret]:
        """Recursively extract token-like values from JSON."""
        if not isinstance(data, dict):
            return

        token_keys = [
            "token",
            "access_token",
            "refresh_token",
            "api_token",
            "xoxb",
            "xoxp",
            "xoxa",
        ]

        for key, value in data.items():
            full_key = f"{prefix}/{key}" if prefix else key

            if isinstance(value, str):
                # Check if this looks like a token
                key_lower = key.lower()
                is_token_key = any(tk in key_lower for tk in token_keys)
                is_token_value = value.startswith(("xoxb-", "xoxp-", "xoxa-", "xoxs-"))

                if is_token_key or is_token_value:
                    yield GatheredSecret(
                        value=value,
                        metadata=SecretMetadata(
                            source_type=self.source_type,
                            source_path=str(creds_path),
                            secret_name=full_key,
                        ),
                    )
            elif isinstance(value, dict):
                yield from self._extract_tokens(value, creds_path, full_key)
