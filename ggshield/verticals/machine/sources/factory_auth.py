"""
Factory CLI authentication source.

Scans ~/.factory/auth.json for authentication tokens.
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


class FactoryAuthSource(SecretSource):
    """Collects secrets from Factory CLI authentication."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.FACTORY_AUTH

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from Factory CLI auth files.

        Checks:
        - ~/.factory/auth.json (authentication tokens)
        """
        factory_dir = self._home_dir / ".factory"
        if not factory_dir.exists() or not factory_dir.is_dir():
            return

        # Check auth.json
        auth_path = factory_dir / "auth.json"
        if auth_path.exists() and auth_path.is_file():
            yield from self._gather_from_auth(auth_path)

    def _gather_from_auth(self, auth_path: Path) -> Iterator[GatheredSecret]:
        """Extract authentication tokens from auth.json."""
        try:
            content = auth_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        try:
            auth = json.loads(content)
        except json.JSONDecodeError:
            return

        # Token fields commonly found in auth files
        token_fields = [
            "access_token",
            "accessToken",
            "refresh_token",
            "refreshToken",
            "id_token",
            "idToken",
            "token",
            "api_key",
            "apiKey",
            "api_token",
            "apiToken",
            "auth_token",
            "authToken",
            "bearer_token",
            "bearerToken",
            "jwt",
            "session_token",
            "sessionToken",
        ]

        for field in token_fields:
            value = auth.get(field)
            if value and isinstance(value, str) and len(value) > 5:
                yield GatheredSecret(
                    value=value,
                    metadata=SecretMetadata(
                        source_type=self.source_type,
                        source_path=str(auth_path),
                        secret_name=field,
                    ),
                )

        # Also check nested structures (e.g., {"auth": {"token": "xxx"}})
        if isinstance(auth.get("auth"), dict):
            for field in token_fields:
                value = auth["auth"].get(field)
                if value and isinstance(value, str) and len(value) > 5:
                    yield GatheredSecret(
                        value=value,
                        metadata=SecretMetadata(
                            source_type=self.source_type,
                            source_path=str(auth_path),
                            secret_name=f"auth.{field}",
                        ),
                    )
