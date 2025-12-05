"""
Unified filesystem walker for single-pass secret scanning.

This module provides a single os.walk() traversal that dispatches files
to multiple FileMatcher implementations, eliminating duplicate filesystem scans.
"""

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Pattern, Set

from ggshield.verticals.machine.sources import GatheredSecret, SourceType
from ggshield.verticals.machine.sources.file_matcher import FileMatcher


# Directories to skip during traversal (common to all matchers)
SKIP_DIRECTORIES = {
    "node_modules",
    "__pycache__",
    ".git",
    ".hg",
    ".svn",
    ".cache",
    ".venv",
    "venv",
    ".tox",
    "dist",
    "build",
    "target",
}

# Progress update interval in seconds
PROGRESS_INTERVAL_SECONDS = 0.2


@dataclass
class WalkerStats:
    """Statistics from the unified walk."""

    files_visited: int = 0
    matches_by_type: Dict[SourceType, int] = field(default_factory=dict)
    secrets_by_type: Dict[SourceType, int] = field(default_factory=dict)


# Type for progress callback: (files_visited, matches_by_type) -> None
WalkerProgressCallback = Callable[[int, Dict[SourceType, int]], None]


@dataclass
class WalkerConfig:
    """Configuration for the unified filesystem walker."""

    home_dir: Path
    matchers: List[FileMatcher]
    is_timed_out: Callable[[], bool]
    exclusion_regexes: Set[Pattern[str]] = field(default_factory=set)
    on_progress: Optional[WalkerProgressCallback] = None


class UnifiedFileSystemWalker:
    """
    Performs a single filesystem traversal dispatching to multiple matchers.

    This replaces separate EnvFileSource and PrivateKeySource os.walk() calls
    with a single pass, reducing filesystem I/O by ~50%.

    Performance optimizations:
    - String-based filename matching (no Path object creation in hot loop)
    - Pre-computed union of allowed dot directories
    - Time-based progress throttling to avoid callback overhead
    """

    def __init__(self, config: WalkerConfig):
        self.config = config
        self._stats = WalkerStats()
        self._last_progress_time = 0.0

        # Pre-compute union of allowed dot directories from all matchers
        self._allowed_dot_dirs: Set[str] = set()
        for matcher in config.matchers:
            self._allowed_dot_dirs.update(matcher.allowed_dot_directories)

        # Initialize match counts for each matcher's source type
        for matcher in config.matchers:
            self._stats.matches_by_type[matcher.source_type] = 0
            self._stats.secrets_by_type[matcher.source_type] = 0

    def walk(self) -> Iterator[GatheredSecret]:
        """
        Walk the filesystem and yield secrets from all matchers.

        Uses a single os.walk() traversal, dispatching files to matchers
        based on filename patterns. Path objects are only created for
        files that match at least one matcher.

        Yields:
            GatheredSecret instances from all matched files
        """
        for root, dirs, files in os.walk(self.config.home_dir):
            self._stats.files_visited += len(files)

            # Report progress periodically (time-based throttling)
            self._maybe_report_progress()

            if self.config.is_timed_out():
                return

            # Prune directories we don't want to traverse
            self._prune_directories(dirs)

            # Process files with string-based matching first (PERF: no Path creation)
            for filename in files:
                # Find first matcher that matches this filename
                for matcher in self.config.matchers:
                    if matcher.matches_filename(filename):
                        # Only create Path for matched files
                        file_path = Path(root) / filename

                        # Extract secrets and track stats
                        # Track secrets count separately from file matches
                        secrets_from_file = 0
                        for secret in matcher.extract_secrets(
                            file_path, self.config.exclusion_regexes
                        ):
                            secrets_from_file += 1
                            self._stats.secrets_by_type[matcher.source_type] += 1
                            yield secret

                        # Only count as matched file if we found secrets
                        if secrets_from_file > 0:
                            self._stats.matches_by_type[matcher.source_type] += 1

                        # First matcher wins (no double-extraction)
                        break

    def _prune_directories(self, dirs: List[str]) -> None:
        """
        Remove directories we should skip from the traversal list.

        Modifies dirs in-place to prevent os.walk from descending
        into unwanted directories.
        """
        indices_to_remove = []

        for i, dirname in enumerate(dirs):
            if dirname in SKIP_DIRECTORIES:
                indices_to_remove.append(i)
            elif dirname.startswith("."):
                # Skip hidden dirs except allowed ones
                # Check if dirname matches or starts with any allowed directory
                if not any(
                    dirname == allowed or dirname.startswith(allowed)
                    for allowed in self._allowed_dot_dirs
                ):
                    indices_to_remove.append(i)

        # Remove in reverse order to preserve indices
        for i in reversed(indices_to_remove):
            del dirs[i]

    def _maybe_report_progress(self) -> None:
        """Report progress if enough time has passed."""
        if self.config.on_progress is None:
            return

        now = time.time()
        if now - self._last_progress_time >= PROGRESS_INTERVAL_SECONDS:
            self._last_progress_time = now
            self.config.on_progress(
                self._stats.files_visited,
                dict(self._stats.matches_by_type),
            )

    @property
    def stats(self) -> WalkerStats:
        """Return walker statistics."""
        return self._stats
