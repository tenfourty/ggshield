"""
Travis CI CLI configuration source.

Scans ~/.travis/config.yml for API tokens.
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


# Pattern to match access_token in YAML
TOKEN_PATTERN = re.compile(r"^\s*access_token:\s*(.+?)\s*$", re.MULTILINE)


class TravisCIConfigSource(SecretSource):
    """Collects secrets from Travis CI CLI config."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.TRAVIS_CI_CONFIG

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from Travis CI CLI config.

        The file structure is:
        endpoints:
          https://api.travis-ci.com/:
            access_token: <token>
        """
        config_path = self._home_dir / ".travis" / "config.yml"
        if not config_path.exists() or not config_path.is_file():
            return

        try:
            content = config_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        # Extract access tokens
        for match in TOKEN_PATTERN.finditer(content):
            token = match.group(1).strip()
            # Remove quotes if present
            if (token.startswith('"') and token.endswith('"')) or (
                token.startswith("'") and token.endswith("'")
            ):
                token = token[1:-1]

            if token:
                yield GatheredSecret(
                    value=token,
                    metadata=SecretMetadata(
                        source_type=self.source_type,
                        source_path=str(config_path),
                        secret_name="access_token",
                    ),
                )
