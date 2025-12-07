"""
PyPI configuration file secret source.
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

# Section header pattern
SECTION_PATTERN = re.compile(r"^\s*\[([^\]]+)\]\s*$")

# PyPI credential keys that contain secrets
PYPI_SECRET_KEYS = {
    "password",
    "token",
}


class PypircSource(SecretSource):
    """Collects secrets from ~/.pypirc configuration."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise PyPI config source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.PYPIRC

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from ~/.pypirc file.

        Extracts password and token values from the PyPI configuration file.
        """
        pypirc_path = self._home_dir / ".pypirc"
        if not pypirc_path.exists() or not pypirc_path.is_file():
            return

        try:
            content = pypirc_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        current_section = ""

        for line in content.splitlines():
            # Track section headers
            section_match = SECTION_PATTERN.match(line)
            if section_match:
                current_section = section_match.group(1).strip()
                continue

            match = INI_LINE_PATTERN.match(line)
            if not match:
                continue

            key, value = match.groups()
            key_lower = key.lower().strip()

            # Only yield secret keys
            if key_lower not in PYPI_SECRET_KEYS:
                continue

            # Build descriptive name including section
            secret_name = (
                f"{current_section}/{key_lower}" if current_section else key_lower
            )

            yield GatheredSecret(
                value=value,
                metadata=SecretMetadata(
                    source_type=self.source_type,
                    source_path=str(pypirc_path),
                    secret_name=secret_name,
                ),
            )
