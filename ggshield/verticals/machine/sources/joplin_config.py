"""
Joplin configuration source.

Scans ~/.config/joplin-desktop/settings.json for cloud sync tokens.
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


class JoplinConfigSource(SecretSource):
    """Collects secrets from Joplin configuration."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.JOPLIN_CONFIG

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from Joplin config files.

        Checks:
        - ~/.config/joplin-desktop/settings.json (cloud sync tokens)
        """
        config_dir = self._home_dir / ".config" / "joplin-desktop"
        if not config_dir.exists() or not config_dir.is_dir():
            return

        # Check settings.json
        settings_path = config_dir / "settings.json"
        if settings_path.exists() and settings_path.is_file():
            yield from self._gather_from_settings(settings_path)

    def _gather_from_settings(self, settings_path: Path) -> Iterator[GatheredSecret]:
        """Extract sync tokens from settings.json."""
        try:
            content = settings_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        try:
            settings = json.loads(content)
        except json.JSONDecodeError:
            return

        # Joplin sync-related keys that may contain tokens
        # See: https://joplinapp.org/help/apps/sync/
        sync_token_fields = [
            # Joplin Cloud / Server
            "sync.10.password",  # Joplin Cloud password/token
            "sync.5.password",  # Joplin Server password
            "sync.9.password",  # Joplin Cloud (old numbering)
            # Dropbox
            "sync.7.auth",  # Dropbox OAuth token
            # OneDrive
            "sync.3.auth",  # OneDrive OAuth token
            # WebDAV
            "sync.6.password",  # WebDAV password
            # S3
            "sync.8.password",  # S3 secret key
            # Generic token fields
            "api.token",
            "encryption.masterPassword",
        ]

        for field in sync_token_fields:
            value = settings.get(field)
            if value and isinstance(value, str) and len(value) > 5:
                yield GatheredSecret(
                    value=value,
                    metadata=SecretMetadata(
                        source_type=self.source_type,
                        source_path=str(settings_path),
                        secret_name=field,
                    ),
                )

        # Also check for any keys ending in common secret patterns
        secret_suffixes = [".password", ".auth", ".token", ".secret", ".key"]
        for key, value in settings.items():
            if any(key.endswith(suffix) for suffix in secret_suffixes):
                if key not in sync_token_fields:  # Avoid duplicates
                    if value and isinstance(value, str) and len(value) > 5:
                        yield GatheredSecret(
                            value=value,
                            metadata=SecretMetadata(
                                source_type=self.source_type,
                                source_path=str(settings_path),
                                secret_name=key,
                            ),
                        )
