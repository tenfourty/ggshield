"""
Helm registry configuration source.

Scans ~/.config/helm/registry/config.json for OCI registry credentials.
"""

import base64
import json
from pathlib import Path
from typing import Iterator, Optional

from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)
from ggshield.verticals.machine.sources.base import SecretSource


class HelmConfigSource(SecretSource):
    """Collects secrets from Helm registry config."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.HELM_CONFIG

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from Helm registry config.

        Uses same format as Docker config.json with base64-encoded auth.
        """
        config_path = self._home_dir / ".config" / "helm" / "registry" / "config.json"
        if not config_path.exists() or not config_path.is_file():
            return

        try:
            content = config_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        try:
            config = json.loads(content)
        except json.JSONDecodeError:
            return

        # Same structure as Docker config: {"auths": {"registry": {"auth": "base64"}}}
        auths = config.get("auths", {})
        if not isinstance(auths, dict):
            return

        for registry, auth_data in auths.items():
            if not isinstance(auth_data, dict):
                continue

            auth_value = auth_data.get("auth")
            if not auth_value or not isinstance(auth_value, str):
                continue

            # Try to decode base64 to extract password
            try:
                decoded = base64.b64decode(auth_value).decode("utf-8", errors="ignore")
                if ":" in decoded:
                    # Format is username:password
                    password = decoded.split(":", 1)[1]
                    if password:
                        yield GatheredSecret(
                            value=password,
                            metadata=SecretMetadata(
                                source_type=self.source_type,
                                source_path=str(config_path),
                                secret_name=f"{registry}/password",
                            ),
                        )
                        continue
                # Decoded but not in expected format, yield raw auth
                yield GatheredSecret(
                    value=auth_value,
                    metadata=SecretMetadata(
                        source_type=self.source_type,
                        source_path=str(config_path),
                        secret_name=f"{registry}/auth",
                    ),
                )
            except Exception:
                # If decoding fails, yield the raw auth value
                yield GatheredSecret(
                    value=auth_value,
                    metadata=SecretMetadata(
                        source_type=self.source_type,
                        source_path=str(config_path),
                        secret_name=f"{registry}/auth",
                    ),
                )
