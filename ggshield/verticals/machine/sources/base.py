"""
Abstract base class for secret sources.
"""

from abc import ABC, abstractmethod
from typing import Iterator

from ggshield.verticals.machine.sources import GatheredSecret, SourceType


class SecretSource(ABC):
    """
    Abstract base class for secret sources.

    Each source implementation is responsible for gathering secrets
    from a specific location (environment variables, files, etc.).
    """

    @property
    @abstractmethod
    def source_type(self) -> SourceType:
        """Return the type of this source."""
        pass

    @abstractmethod
    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from this source.

        This method should be a generator that yields secrets as they
        are discovered, enabling streaming processing and timeout
        handling.
        """
        pass
