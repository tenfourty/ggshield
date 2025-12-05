"""
Environment variable secret source.
"""

import os
from typing import Iterator

from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)
from ggshield.verticals.machine.sources.base import SecretSource


# Keys that are typically not secrets and should be excluded
EXCLUDED_ENV_KEYS = {
    "HOME",
    "HOSTNAME",
    "HOST",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "LOGNAME",
    "MAIL",
    "OLDPWD",
    "PATH",
    "PORT",
    "PS1",
    "PS2",
    "PWD",
    "SHELL",
    "SHLVL",
    "TERM",
    "TERM_PROGRAM",
    "TERM_PROGRAM_VERSION",
    "TMPDIR",
    "USER",
    "USERNAME",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
    "_",
}


class EnvironmentSecretSource(SecretSource):
    """Collects secrets from environment variables."""

    @property
    def source_type(self) -> SourceType:
        return SourceType.ENVIRONMENT_VAR

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield potential secrets from environment variables.

        Excludes common non-secret environment variables like PATH, HOME, etc.
        """
        for name, value in os.environ.items():
            # Skip excluded keys
            if name.upper() in EXCLUDED_ENV_KEYS:
                continue

            yield GatheredSecret(
                value=value,
                metadata=SecretMetadata(
                    source_type=self.source_type,
                    source_path="environment",
                    secret_name=name,
                ),
            )
