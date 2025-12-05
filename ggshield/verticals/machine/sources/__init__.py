"""
Secret source definitions and types for machine scanning.
"""

from dataclasses import dataclass
from enum import Enum, auto


class SourceType(Enum):
    """Types of secret sources on the machine."""

    ENVIRONMENT_VAR = auto()
    GITHUB_TOKEN = auto()
    NPMRC = auto()
    ENV_FILE = auto()
    PRIVATE_KEY = auto()


@dataclass
class SecretMetadata:
    """Metadata about where a secret was discovered."""

    source_type: SourceType
    source_path: str
    secret_name: str


@dataclass
class GatheredSecret:
    """A secret discovered during machine scanning."""

    value: str
    metadata: SecretMetadata


__all__ = [
    "GatheredSecret",
    "SecretMetadata",
    "SourceType",
]
