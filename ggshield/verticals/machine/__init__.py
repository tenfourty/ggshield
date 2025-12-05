"""
Machine-wide secret scanning functionality.

This module provides tools for scanning a local machine for secrets
from various sources (environment variables, configuration files,
private keys, etc.) and optionally checking if they have been
publicly exposed.
"""

from ggshield.verticals.machine.secret_gatherer import (
    GatheringConfig,
    GatheringStats,
    MachineSecretGatherer,
)
from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)


__all__ = [
    "GatheringConfig",
    "GatheringStats",
    "GatheredSecret",
    "MachineSecretGatherer",
    "SecretMetadata",
    "SourceType",
]
