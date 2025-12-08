"""
GitLab CLI (glab) configuration source.

Scans ~/.config/glab-cli/config.yml for API tokens.
On Windows, scans %APPDATA%/glab-cli/config.yml instead.
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
from ggshield.verticals.machine.sources.platform_paths import get_appdata, is_windows


# Pattern to match token in YAML
TOKEN_PATTERN = re.compile(r"^\s*token:\s*(.+?)\s*$", re.MULTILINE)
# Pattern to match host sections
HOST_PATTERN = re.compile(r"^\s*-?\s*hosts?:\s*$|^(\S+):$", re.MULTILINE)


class GitLabCliSource(SecretSource):
    """Collects secrets from GitLab CLI (glab) config."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.GITLAB_CLI

    def _get_config_path(self) -> Optional[Path]:
        """Get the config file path based on the current platform."""
        if is_windows():
            appdata = get_appdata()
            if appdata:
                return appdata / "glab-cli" / "config.yml"
            return None
        return self._home_dir / ".config" / "glab-cli" / "config.yml"

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from GitLab CLI config.

        The file structure is:
        hosts:
          gitlab.com:
            token: <token>
            git_protocol: ssh
          gitlab.example.com:
            token: <token>
        """
        config_path = self._get_config_path()
        if config_path is None or not config_path.exists() or not config_path.is_file():
            return

        try:
            content = config_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        # Extract tokens with their associated hosts using simple parsing
        lines = content.splitlines()
        current_host = None
        in_hosts_section = False

        for line in lines:
            stripped = line.strip()

            # Check for hosts section
            if stripped == "hosts:" or stripped.startswith("hosts:"):
                in_hosts_section = True
                continue

            if in_hosts_section:
                # Check for host entry (indented key ending with :)
                if line.startswith("  ") and not line.startswith("    "):
                    host_match = re.match(r"^\s{2}(\S+):\s*$", line)
                    if host_match:
                        current_host = host_match.group(1)
                        continue

                # Check for token under host
                if current_host and line.startswith("    "):
                    token_match = re.match(r"^\s{4}token:\s*(.+?)\s*$", line)
                    if token_match:
                        token = token_match.group(1).strip()
                        # Remove quotes if present
                        if (token.startswith('"') and token.endswith('"')) or (
                            token.startswith("'") and token.endswith("'")
                        ):
                            token = token[1:-1]

                        if token:
                            yield GatheredSecret(
                                value=token,
                                metadata=SecretMetadata(
                                    source_type=self.source_type,
                                    source_path=str(config_path),
                                    secret_name=f"{current_host}/token",
                                ),
                            )

                # Reset if we hit a new top-level section
                if line and not line.startswith(" "):
                    in_hosts_section = False
                    current_host = None
