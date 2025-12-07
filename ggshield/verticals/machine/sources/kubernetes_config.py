"""
Kubernetes kubeconfig file secret source.
"""

from pathlib import Path
from typing import Any, Dict, Iterator, Optional

from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)
from ggshield.verticals.machine.sources.base import SecretSource


class KubernetesConfigSource(SecretSource):
    """Collects secrets from ~/.kube/config configuration."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise Kubernetes config source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.KUBERNETES_CONFIG

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from ~/.kube/config file.

        Extracts tokens, passwords, and client key data from kubeconfig.
        """
        kubeconfig_path = self._home_dir / ".kube" / "config"
        if not kubeconfig_path.exists() or not kubeconfig_path.is_file():
            return

        try:
            content = kubeconfig_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        # Try to parse as YAML
        try:
            import yaml

            config = yaml.safe_load(content)
        except ImportError:
            # YAML not available, try basic extraction
            yield from self._extract_without_yaml(content, kubeconfig_path)
            return
        except Exception:
            return

        if not isinstance(config, dict):
            return

        # Extract secrets from users section
        users = config.get("users", [])
        if not isinstance(users, list):
            return

        for user_entry in users:
            if not isinstance(user_entry, dict):
                continue

            user_name = user_entry.get("name", "unknown")
            user_config = user_entry.get("user", {})

            if not isinstance(user_config, dict):
                continue

            yield from self._extract_user_secrets(
                user_name, user_config, kubeconfig_path
            )

    def _extract_user_secrets(
        self, user_name: str, user_config: Dict[str, Any], config_path: Path
    ) -> Iterator[GatheredSecret]:
        """Extract secrets from a user configuration block."""
        # Token (bearer token for authentication)
        token = user_config.get("token")
        if token and isinstance(token, str):
            yield GatheredSecret(
                value=token,
                metadata=SecretMetadata(
                    source_type=self.source_type,
                    source_path=str(config_path),
                    secret_name=f"users/{user_name}/token",
                ),
            )

        # Password (basic auth)
        password = user_config.get("password")
        if password and isinstance(password, str):
            yield GatheredSecret(
                value=password,
                metadata=SecretMetadata(
                    source_type=self.source_type,
                    source_path=str(config_path),
                    secret_name=f"users/{user_name}/password",
                ),
            )

        # Client key data (base64 encoded private key)
        client_key_data = user_config.get("client-key-data")
        if client_key_data and isinstance(client_key_data, str):
            yield GatheredSecret(
                value=client_key_data,
                metadata=SecretMetadata(
                    source_type=self.source_type,
                    source_path=str(config_path),
                    secret_name=f"users/{user_name}/client-key-data",
                ),
            )

        # Auth provider config (e.g., GKE, EKS tokens)
        auth_provider = user_config.get("auth-provider", {})
        if isinstance(auth_provider, dict):
            auth_config = auth_provider.get("config", {})
            if isinstance(auth_config, dict):
                # Access token
                access_token = auth_config.get("access-token")
                if access_token and isinstance(access_token, str):
                    yield GatheredSecret(
                        value=access_token,
                        metadata=SecretMetadata(
                            source_type=self.source_type,
                            source_path=str(config_path),
                            secret_name=f"users/{user_name}/auth-provider/access-token",
                        ),
                    )

                # ID token
                id_token = auth_config.get("id-token")
                if id_token and isinstance(id_token, str):
                    yield GatheredSecret(
                        value=id_token,
                        metadata=SecretMetadata(
                            source_type=self.source_type,
                            source_path=str(config_path),
                            secret_name=f"users/{user_name}/auth-provider/id-token",
                        ),
                    )

    def _extract_without_yaml(
        self, content: str, config_path: Path
    ) -> Iterator[GatheredSecret]:
        """
        Basic extraction when PyYAML is not available.

        Uses simple string matching for common secret patterns.
        """
        import re

        # Patterns for secrets in YAML format
        patterns = [
            (r"^\s*token:\s*(.+?)\s*$", "token"),
            (r"^\s*password:\s*(.+?)\s*$", "password"),
            (r"^\s*client-key-data:\s*(.+?)\s*$", "client-key-data"),
            (r"^\s*access-token:\s*(.+?)\s*$", "access-token"),
            (r"^\s*id-token:\s*(.+?)\s*$", "id-token"),
        ]

        for line in content.splitlines():
            for pattern, key_name in patterns:
                match = re.match(pattern, line)
                if match:
                    value = match.group(1).strip()
                    # Skip quoted empty strings
                    if value in ('""', "''", ""):
                        continue
                    # Remove surrounding quotes if present
                    if (value.startswith('"') and value.endswith('"')) or (
                        value.startswith("'") and value.endswith("'")
                    ):
                        value = value[1:-1]
                    if value:
                        yield GatheredSecret(
                            value=value,
                            metadata=SecretMetadata(
                                source_type=self.source_type,
                                source_path=str(config_path),
                                secret_name=key_name,
                            ),
                        )
