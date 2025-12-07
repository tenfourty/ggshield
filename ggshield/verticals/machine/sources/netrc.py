"""
Netrc file secret source.
"""

from pathlib import Path
from typing import Iterator, Optional

from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)
from ggshield.verticals.machine.sources.base import SecretSource


class NetrcSource(SecretSource):
    """Collects secrets from ~/.netrc (or ~/_netrc on Windows)."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise netrc source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.NETRC

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from ~/.netrc file.

        Extracts password values from the netrc file format.
        Format: machine <host> login <user> password <token>
        """
        # Check both .netrc and _netrc (Windows)
        netrc_paths = [
            self._home_dir / ".netrc",
            self._home_dir / "_netrc",
        ]

        for netrc_path in netrc_paths:
            if not netrc_path.exists() or not netrc_path.is_file():
                continue

            try:
                content = netrc_path.read_text(encoding="utf-8", errors="ignore")
            except (OSError, PermissionError):
                continue

            yield from self._parse_netrc(content, netrc_path)

    def _parse_netrc(self, content: str, file_path: Path) -> Iterator[GatheredSecret]:
        """Parse netrc format and extract password values."""
        # Netrc format can be multiline or single-line per machine
        # machine <host> login <user> password <password>

        # Tokenize the content
        tokens = content.split()

        current_machine = None
        i = 0

        while i < len(tokens):
            token = tokens[i].lower()

            if token == "machine" and i + 1 < len(tokens):
                current_machine = tokens[i + 1]
                i += 2
            elif token == "default":
                current_machine = "default"
                i += 1
            elif token == "login" and i + 1 < len(tokens):
                i += 2  # Skip login and its value
            elif token == "password" and i + 1 < len(tokens):
                password = tokens[i + 1]
                machine_name = current_machine or "unknown"

                yield GatheredSecret(
                    value=password,
                    metadata=SecretMetadata(
                        source_type=self.source_type,
                        source_path=str(file_path),
                        secret_name=f"{machine_name}/password",
                    ),
                )
                i += 2
            elif token == "account" and i + 1 < len(tokens):
                i += 2  # Skip account and its value
            elif token == "macdef":
                # Macro definition - skip until blank line
                # This is complex, for now just skip the macdef token
                i += 1
            else:
                i += 1
