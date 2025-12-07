"""
Git credentials file secret source.
"""

from pathlib import Path
from typing import Iterator, Optional
from urllib.parse import urlparse

from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)
from ggshield.verticals.machine.sources.base import SecretSource


class GitCredentialsSource(SecretSource):
    """Collects secrets from ~/.git-credentials file."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise git credentials source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.GIT_CREDENTIALS

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from ~/.git-credentials file.

        Format: https://username:password@host
        """
        credentials_path = self._home_dir / ".git-credentials"
        if not credentials_path.exists() or not credentials_path.is_file():
            return

        try:
            content = credentials_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            yield from self._parse_credential_url(line, credentials_path)

    def _parse_credential_url(
        self, url: str, file_path: Path
    ) -> Iterator[GatheredSecret]:
        """Parse a git credential URL and extract the password."""
        try:
            parsed = urlparse(url)
        except ValueError:
            return

        # Check if there's a password in the URL
        if not parsed.password:
            return

        # Build a descriptive name
        host = parsed.hostname or "unknown"
        username = parsed.username or "unknown"

        yield GatheredSecret(
            value=parsed.password,
            metadata=SecretMetadata(
                source_type=self.source_type,
                source_path=str(file_path),
                secret_name=f"{host}/{username}",
            ),
        )
