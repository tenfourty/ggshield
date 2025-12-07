"""
Gradle properties credentials source.

Scans ~/.gradle/gradle.properties for Maven/Gradle registry credentials.
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


# Properties that typically contain secrets
SECRET_PROPERTY_PATTERNS = [
    r".*password.*",
    r".*secret.*",
    r".*token.*",
    r".*apikey.*",
    r".*api_key.*",
    r".*api-key.*",
    r".*credential.*",
    r".*auth.*",
    r"mavenuser",  # Maven Central credentials
    r"ossrhusername",  # Sonatype OSSRH
    r"ossrhpassword",
    r"signingkey.*",
    r"signing\..*",
]

# Compiled pattern for matching secret property names (case-insensitive)
SECRET_PATTERN = re.compile(
    "|".join(f"^{p}$" for p in SECRET_PROPERTY_PATTERNS),
    re.IGNORECASE,
)

# Properties line pattern: key=value or key:value
PROPERTY_LINE_PATTERN = re.compile(r"^\s*([^#=:\s][^=:]*?)\s*[=:]\s*(.+?)\s*$")


class GradlePropertiesSource(SecretSource):
    """Collects secrets from Gradle properties files."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.GRADLE_PROPERTIES

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from gradle.properties.

        Looks for properties with names suggesting credentials.
        """
        props_path = self._home_dir / ".gradle" / "gradle.properties"
        if not props_path.exists() or not props_path.is_file():
            return

        try:
            content = props_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        for line in content.splitlines():
            match = PROPERTY_LINE_PATTERN.match(line)
            if not match:
                continue

            key, value = match.groups()

            # Check if property name suggests a secret
            if SECRET_PATTERN.match(key):
                yield GatheredSecret(
                    value=value,
                    metadata=SecretMetadata(
                        source_type=self.source_type,
                        source_path=str(props_path),
                        secret_name=key,
                    ),
                )
