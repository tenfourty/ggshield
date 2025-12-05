"""
NPM configuration file secret source.
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


# Pattern to extract key=value from npmrc
NPMRC_LINE_PATTERN = re.compile(r"^\s*([^#=\s][^=]*?)\s*=\s*(.+?)\s*$")

# Keys that likely contain secrets
SECRET_NPMRC_KEYS = {
    "_auth",
    "_authtoken",
    "_password",
    "//registry.npmjs.org/:_authtoken",
}

# Pattern to detect auth tokens in npmrc keys
AUTH_KEY_PATTERN = re.compile(r"(_auth|_authtoken|_password|:_auth)", re.IGNORECASE)


class NpmrcSource(SecretSource):
    """Collects secrets from ~/.npmrc configuration."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialize npmrc source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.NPMRC

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from ~/.npmrc file.

        Extracts authentication tokens and other credential-like values
        from the npm configuration file.
        """
        npmrc_path = self._home_dir / ".npmrc"
        if not npmrc_path.exists() or not npmrc_path.is_file():
            return

        try:
            content = npmrc_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        for line in content.splitlines():
            match = NPMRC_LINE_PATTERN.match(line)
            if not match:
                continue

            key, value = match.groups()

            # Only yield values that look like authentication credentials
            if not self._is_auth_key(key):
                continue

            yield GatheredSecret(
                value=value,
                metadata=SecretMetadata(
                    source_type=self.source_type,
                    source_path=str(npmrc_path),
                    secret_name=key,
                ),
            )

    def _is_auth_key(self, key: str) -> bool:
        """Check if the key looks like an authentication credential key."""
        key_lower = key.lower()
        return (
            key_lower in SECRET_NPMRC_KEYS or AUTH_KEY_PATTERN.search(key) is not None
        )
