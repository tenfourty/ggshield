"""
AWS credentials file secret source.
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


# Pattern to extract key=value from INI-style files
INI_LINE_PATTERN = re.compile(r"^\s*([^#=\s][^=]*?)\s*=\s*(.+?)\s*$")

# AWS credential keys that contain secrets
AWS_SECRET_KEYS = {
    "aws_secret_access_key",
    "aws_session_token",
}


class AwsCredentialsSource(SecretSource):
    """Collects secrets from ~/.aws/credentials configuration."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise AWS credentials source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.AWS_CREDENTIALS

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from ~/.aws/credentials file.

        Extracts aws_secret_access_key and aws_session_token values
        from the AWS credentials file.
        """
        credentials_path = self._home_dir / ".aws" / "credentials"
        if not credentials_path.exists() or not credentials_path.is_file():
            return

        try:
            content = credentials_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        current_profile = "default"

        for line in content.splitlines():
            line = line.strip()

            # Track profile sections
            if line.startswith("[") and line.endswith("]"):
                current_profile = line[1:-1].strip()
                continue

            match = INI_LINE_PATTERN.match(line)
            if not match:
                continue

            key, value = match.groups()
            key_lower = key.lower().strip()

            # Only yield secret keys
            if key_lower not in AWS_SECRET_KEYS:
                continue

            # Build descriptive name including profile
            secret_name = f"{current_profile}/{key_lower}"

            yield GatheredSecret(
                value=value,
                metadata=SecretMetadata(
                    source_type=self.source_type,
                    source_path=str(credentials_path),
                    secret_name=secret_name,
                ),
            )
