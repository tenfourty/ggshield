"""
PostgreSQL password file source.

Scans ~/.pgpass for database credentials.
"""

from pathlib import Path
from typing import Iterator, Optional

from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)
from ggshield.verticals.machine.sources.base import SecretSource


class PgpassSource(SecretSource):
    """Collects secrets from PostgreSQL .pgpass file."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.PGPASS

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from .pgpass file.

        Format: hostname:port:database:username:password
        Lines starting with # are comments.
        """
        pgpass_path = self._home_dir / ".pgpass"
        if not pgpass_path.exists() or not pgpass_path.is_file():
            return

        try:
            content = pgpass_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        for line in content.splitlines():
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            # Format: hostname:port:database:username:password
            # Colons can be escaped with backslash
            parts = line.split(":")
            if len(parts) >= 5:
                # Last part is password, rejoin in case password contains colons
                hostname = parts[0]
                database = parts[2]
                username = parts[3]
                password = ":".join(parts[4:])

                if password and password != "*":
                    # Build descriptive name
                    name = f"{hostname}/{database}/{username}"
                    yield GatheredSecret(
                        value=password,
                        metadata=SecretMetadata(
                            source_type=self.source_type,
                            source_path=str(pgpass_path),
                            secret_name=name,
                        ),
                    )
