"""
Azure CLI credentials source.

Scans ~/.azure/ for access tokens and refresh tokens.
"""

import json
from pathlib import Path
from typing import Iterator, Optional

from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)
from ggshield.verticals.machine.sources.base import SecretSource


class AzureCliSource(SecretSource):
    """Collects secrets from Azure CLI credential files."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.AZURE_CLI

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from Azure CLI credential files.

        Checks both msal_token_cache.json and accessTokens.json (legacy).
        """
        azure_dir = self._home_dir / ".azure"
        if not azure_dir.exists() or not azure_dir.is_dir():
            return

        # Check MSAL token cache (modern)
        yield from self._gather_from_msal_cache(azure_dir / "msal_token_cache.json")

        # Check legacy access tokens file
        yield from self._gather_from_access_tokens(azure_dir / "accessTokens.json")

    def _gather_from_msal_cache(self, cache_path: Path) -> Iterator[GatheredSecret]:
        """Extract tokens from MSAL token cache."""
        if not cache_path.exists() or not cache_path.is_file():
            return

        try:
            content = cache_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        try:
            cache = json.loads(content)
        except json.JSONDecodeError:
            return

        # MSAL cache structure has AccessToken, RefreshToken, IdToken sections
        for token_type in ["AccessToken", "RefreshToken", "IdToken"]:
            tokens = cache.get(token_type, {})
            if isinstance(tokens, dict):
                for key, token_data in tokens.items():
                    if isinstance(token_data, dict):
                        secret = token_data.get("secret")
                        if secret and isinstance(secret, str):
                            # Use a shortened key for readability
                            short_key = key[:50] + "..." if len(key) > 50 else key
                            yield GatheredSecret(
                                value=secret,
                                metadata=SecretMetadata(
                                    source_type=self.source_type,
                                    source_path=str(cache_path),
                                    secret_name=f"{token_type}/{short_key}",
                                ),
                            )

    def _gather_from_access_tokens(self, tokens_path: Path) -> Iterator[GatheredSecret]:
        """Extract tokens from legacy accessTokens.json."""
        if not tokens_path.exists() or not tokens_path.is_file():
            return

        try:
            content = tokens_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        try:
            tokens = json.loads(content)
        except json.JSONDecodeError:
            return

        if not isinstance(tokens, list):
            return

        for i, token_entry in enumerate(tokens):
            if not isinstance(token_entry, dict):
                continue

            # Extract access token and refresh token
            for field in ["accessToken", "refreshToken"]:
                value = token_entry.get(field)
                if value and isinstance(value, str):
                    # Include user/tenant info if available
                    user = token_entry.get("userId", f"entry_{i}")
                    yield GatheredSecret(
                        value=value,
                        metadata=SecretMetadata(
                            source_type=self.source_type,
                            source_path=str(tokens_path),
                            secret_name=f"{user}/{field}",
                        ),
                    )
