"""
RubyGems credentials file secret source.
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


# Pattern to extract :key: value from YAML-like gem credentials
GEM_CREDENTIAL_PATTERN = re.compile(r"^\s*:?([^:]+):\s*(.+?)\s*$")


class GemCredentialsSource(SecretSource):
    """Collects secrets from ~/.gem/credentials configuration."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise RubyGems credentials source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.GEM_CREDENTIALS

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from ~/.gem/credentials file.

        The file is YAML-like with format:
        :rubygems_api_key: <api_key>
        """
        credentials_path = self._home_dir / ".gem" / "credentials"
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

            match = GEM_CREDENTIAL_PATTERN.match(line)
            if not match:
                continue

            key, value = match.groups()
            key = key.strip()
            value = value.strip()

            # Skip empty values
            if not value:
                continue

            # All keys in gem credentials are typically API keys
            yield GatheredSecret(
                value=value,
                metadata=SecretMetadata(
                    source_type=self.source_type,
                    source_path=str(credentials_path),
                    secret_name=key,
                ),
            )
