"""
CircleCI CLI configuration source.

Scans ~/.circleci/cli.yml for API tokens.
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


# Pattern to match token in YAML
TOKEN_PATTERN = re.compile(r"^\s*token:\s*(.+?)\s*$", re.MULTILINE)


class CircleCIConfigSource(SecretSource):
    """Collects secrets from CircleCI CLI config."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.CIRCLECI_CONFIG

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from CircleCI CLI config.

        The file typically contains:
        - host: circleci.com
          token: <api_token>
        """
        config_path = self._home_dir / ".circleci" / "cli.yml"
        if not config_path.exists() or not config_path.is_file():
            return

        try:
            content = config_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        # Simple regex extraction for token values
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
                        secret_name="token",
                    ),
                )
