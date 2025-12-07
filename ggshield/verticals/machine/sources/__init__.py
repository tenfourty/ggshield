"""
Secret source definitions and types for machine scanning.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class SourceType(Enum):
    """Types of secret sources on the machine."""

    ENVIRONMENT_VAR = auto()
    GITHUB_TOKEN = auto()
    NPMRC = auto()
    ENV_FILE = auto()
    PRIVATE_KEY = auto()
    # Cloud providers
    AWS_CREDENTIALS = auto()
    KUBERNETES_CONFIG = auto()
    # Container registries
    DOCKER_CONFIG = auto()
    # Package registries
    PYPIRC = auto()
    CARGO_CREDENTIALS = auto()
    GEM_CREDENTIALS = auto()
    # Other credential files
    VAULT_TOKEN = auto()
    NETRC = auto()
    GIT_CREDENTIALS = auto()
    # Cloud providers (additional)
    GCP_ADC = auto()
    AZURE_CLI = auto()
    # Package managers (additional)
    COMPOSER_AUTH = auto()
    HELM_CONFIG = auto()
    GRADLE_PROPERTIES = auto()
    # CI/CD platforms
    CIRCLECI_CONFIG = auto()
    GITLAB_CLI = auto()
    TRAVIS_CI_CONFIG = auto()
    # Databases
    PGPASS = auto()
    MYSQL_CONFIG = auto()
    # AI coding tools
    CLAUDE_CODE = auto()
    GEMINI_CLI = auto()
    AIDER_CONFIG = auto()
    CONTINUE_CONFIG = auto()
    # Messaging
    SLACK_CREDENTIALS = auto()
    # Generic credential files (catch-all for JSON files with tokens)
    GENERIC_CREDENTIAL = auto()
    # Deep scan (API-based comprehensive scanning)
    DEEP_SCAN = auto()
    # Desktop apps
    RAYCAST_CONFIG = auto()
    JOPLIN_CONFIG = auto()
    FACTORY_AUTH = auto()


@dataclass
class SecretMetadata:
    """Metadata about where a secret was discovered."""

    source_type: SourceType
    source_path: str
    secret_name: str

    # API response fields (only populated for DEEP_SCAN secrets)
    # These store the analysis results to avoid re-calling the API
    detector_name: Optional[str] = field(default=None)
    validity: Optional[str] = field(default=None)
    known_secret: bool = field(default=False)
    incident_url: Optional[str] = field(default=None)
    # Field name where the secret was found (from API matches[].name)
    match_name: Optional[str] = field(default=None)


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
