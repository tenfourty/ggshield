"""
Docker configuration file secret source.
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


class DockerConfigSource(SecretSource):
    """Collects secrets from ~/.docker/config.json configuration."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise Docker config source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.DOCKER_CONFIG

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from ~/.docker/config.json file.

        Extracts base64-encoded auth tokens from Docker registry
        authentication configuration.
        """
        config_path = self._home_dir / ".docker" / "config.json"
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

        # Extract auths section
        auths = config.get("auths", {})
        if not isinstance(auths, dict):
            return

        for registry, auth_config in auths.items():
            if not isinstance(auth_config, dict):
                continue

            # Check for auth field (base64 encoded username:password)
            auth_value = auth_config.get("auth")
            if auth_value and isinstance(auth_value, str):
                # The auth field is base64(username:password)
                # We yield the decoded value if it contains a password
                try:
                    decoded = base64.b64decode(auth_value).decode("utf-8")
                    if ":" in decoded:
                        # Contains username:password, yield the full auth token
                        yield GatheredSecret(
                            value=auth_value,
                            metadata=SecretMetadata(
                                source_type=self.source_type,
                                source_path=str(config_path),
                                secret_name=f"auths/{registry}/auth",
                            ),
                        )
                except (ValueError, UnicodeDecodeError):
                    # If we can't decode, still yield it - it's suspicious
                    yield GatheredSecret(
                        value=auth_value,
                        metadata=SecretMetadata(
                            source_type=self.source_type,
                            source_path=str(config_path),
                            secret_name=f"auths/{registry}/auth",
                        ),
                    )

            # Check for identitytoken (OAuth tokens)
            identity_token = auth_config.get("identitytoken")
            if identity_token and isinstance(identity_token, str):
                yield GatheredSecret(
                    value=identity_token,
                    metadata=SecretMetadata(
                        source_type=self.source_type,
                        source_path=str(config_path),
                        secret_name=f"auths/{registry}/identitytoken",
                    ),
                )

            # Check for registrytoken
            registry_token = auth_config.get("registrytoken")
            if registry_token and isinstance(registry_token, str):
                yield GatheredSecret(
                    value=registry_token,
                    metadata=SecretMetadata(
                        source_type=self.source_type,
                        source_path=str(config_path),
                        secret_name=f"auths/{registry}/registrytoken",
                    ),
                )
