"""
Cargo/crates.io credentials file secret source.
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


# Pattern to extract key=value from TOML files
TOML_LINE_PATTERN = re.compile(r"^\s*([^#=\s][^=]*?)\s*=\s*(.+?)\s*$")

# Section header pattern for TOML
SECTION_PATTERN = re.compile(r"^\s*\[([^\]]+)\]\s*$")


class CargoCredentialsSource(SecretSource):
    """Collects secrets from ~/.cargo/credentials.toml configuration."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise Cargo credentials source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.CARGO_CREDENTIALS

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from ~/.cargo/credentials.toml file.

        Extracts token values from the Cargo credentials file.
        Also checks ~/.cargo/credentials (older format without .toml).
        """
        # Check both old and new credential file names
        credential_paths = [
            self._home_dir / ".cargo" / "credentials.toml",
            self._home_dir / ".cargo" / "credentials",
        ]

        for credentials_path in credential_paths:
            if not credentials_path.exists() or not credentials_path.is_file():
                continue

            try:
                content = credentials_path.read_text(encoding="utf-8", errors="ignore")
            except (OSError, PermissionError):
                continue

            yield from self._parse_credentials(content, credentials_path)
            # Only process the first file found
            break

    def _parse_credentials(
        self, content: str, file_path: Path
    ) -> Iterator[GatheredSecret]:
        """Parse TOML credentials file and extract tokens."""
        current_section = ""

        for line in content.splitlines():
            # Track section headers
            section_match = SECTION_PATTERN.match(line)
            if section_match:
                current_section = section_match.group(1).strip()
                continue

            match = TOML_LINE_PATTERN.match(line)
            if not match:
                continue

            key, value = match.groups()
            key_lower = key.lower().strip()

            # Only yield token keys
            if key_lower != "token":
                continue

            # Clean the value (remove quotes)
            value = value.strip()
            if (value.startswith('"') and value.endswith('"')) or (
                value.startswith("'") and value.endswith("'")
            ):
                value = value[1:-1]

            # Build descriptive name including section
            if current_section:
                secret_name = f"{current_section}/token"
            else:
                secret_name = "token"

            yield GatheredSecret(
                value=value,
                metadata=SecretMetadata(
                    source_type=self.source_type,
                    source_path=str(file_path),
                    secret_name=secret_name,
                ),
            )
