"""
HashiCorp Vault token file secret source.
"""

from pathlib import Path
from typing import Iterator, Optional

from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)
from ggshield.verticals.machine.sources.base import SecretSource


class VaultTokenSource(SecretSource):
    """Collects secrets from ~/.vault-token file."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise Vault token source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.VAULT_TOKEN

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from ~/.vault-token file.

        The file contains a single Vault token in plain text.
        """
        token_path = self._home_dir / ".vault-token"
        if not token_path.exists() or not token_path.is_file():
            return

        try:
            content = token_path.read_text(encoding="utf-8", errors="ignore").strip()
        except (OSError, PermissionError):
            return

        if not content:
            return

        yield GatheredSecret(
            value=content,
            metadata=SecretMetadata(
                source_type=self.source_type,
                source_path=str(token_path),
                secret_name="vault-token",
            ),
        )
