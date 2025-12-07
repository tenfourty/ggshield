"""
MySQL configuration file source.

Scans ~/.my.cnf for database credentials.
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


# Pattern for INI-style key=value
INI_LINE_PATTERN = re.compile(r"^\s*password\s*=\s*(.+?)\s*$", re.IGNORECASE)
SECTION_PATTERN = re.compile(r"^\s*\[([^\]]+)\]\s*$")


class MysqlConfigSource(SecretSource):
    """Collects secrets from MySQL .my.cnf file."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.MYSQL_CONFIG

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from .my.cnf file.

        Looks for password entries in [client], [mysql], [mysqldump] sections.
        """
        config_path = self._home_dir / ".my.cnf"
        if not config_path.exists() or not config_path.is_file():
            return

        try:
            content = config_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        current_section = "default"
        for line in content.splitlines():
            # Check for section header
            section_match = SECTION_PATTERN.match(line)
            if section_match:
                current_section = section_match.group(1).strip()
                continue

            # Check for password
            password_match = INI_LINE_PATTERN.match(line)
            if password_match:
                password = password_match.group(1).strip()
                # Remove quotes if present
                if (password.startswith('"') and password.endswith('"')) or (
                    password.startswith("'") and password.endswith("'")
                ):
                    password = password[1:-1]

                if password:
                    yield GatheredSecret(
                        value=password,
                        metadata=SecretMetadata(
                            source_type=self.source_type,
                            source_path=str(config_path),
                            secret_name=f"{current_section}/password",
                        ),
                    )
