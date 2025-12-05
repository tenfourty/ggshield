"""
Main secret gathering orchestrator for machine scanning.
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Iterator, Optional, Pattern, Set

from ggshield.verticals.machine.sources import GatheredSecret, SourceType
from ggshield.verticals.machine.sources.env_files import EnvFileSource
from ggshield.verticals.machine.sources.environment import EnvironmentSecretSource
from ggshield.verticals.machine.sources.github_token import GitHubTokenSource
from ggshield.verticals.machine.sources.npmrc import NpmrcSource
from ggshield.verticals.machine.sources.private_keys import PrivateKeySource


# Type alias for progress callback: (phase, files_visited, elapsed_seconds) -> None
ProgressCallback = Callable[[str, int, float], None]


class SourceStatus(Enum):
    """Status of a source after scanning."""

    COMPLETED = "completed"
    NOT_FOUND = "not_found"
    SKIPPED = "skipped"


@dataclass
class SourceResult:
    """Result from scanning a single source."""

    source_type: SourceType
    status: SourceStatus
    secrets_found: int = 0
    files_scanned: int = 0
    message: Optional[str] = None  # e.g., "no .npmrc found"


# Type alias for source completion callback
SourceCompletionCallback = Callable[[SourceResult], None]


@dataclass
class GatheringConfig:
    """Configuration for secret gathering."""

    timeout: int = 0  # 0 = no timeout
    min_chars: int = 5
    verbose: bool = False
    home_dir: Optional[Path] = None  # For testing
    on_progress: Optional[ProgressCallback] = field(default=None, repr=False)
    on_source_complete: Optional[SourceCompletionCallback] = field(
        default=None, repr=False
    )
    exclusion_regexes: Set[Pattern[str]] = field(default_factory=set)


@dataclass
class GatheringStats:
    """Statistics from the gathering process."""

    env_vars_count: int = 0
    github_token_found: bool = False
    npmrc_files: int = 0
    npmrc_secrets: int = 0
    env_files: int = 0
    env_secrets: int = 0
    private_key_files: int = 0
    private_key_secrets: int = 0
    total_files_visited: int = 0
    elapsed_seconds: float = 0.0
    timed_out: bool = False


class MachineSecretGatherer:
    """
    Gathers secrets from various machine sources.

    Uses a streaming approach - yields secrets as they're found
    without storing them to disk.
    """

    # Report progress every N files visited
    PROGRESS_INTERVAL = 10000

    def __init__(self, config: GatheringConfig):
        self.config = config
        self._stats = GatheringStats()
        self._start_time: Optional[float] = None
        self._last_progress_files: int = 0

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Gather secrets from all configured sources.

        Yields secrets as they're discovered. Statistics are
        updated incrementally and available via `stats` property.
        """
        self._start_time = time.time()
        self._stats = GatheringStats()

        home = self.config.home_dir or Path.home()

        # Fast sources first (no filesystem traversal)
        yield from self._gather_from_environment()
        yield from self._gather_from_github_cli()
        yield from self._gather_from_npmrc(home)

        # Filesystem sources (respects timeout)
        if not self._is_timed_out():
            self._report_progress_force("Scanning .env files")
            yield from self._gather_from_env_files(home)

        if not self._is_timed_out():
            self._report_progress_force("Scanning for private keys")
            yield from self._gather_from_private_keys(home)

        self._stats.elapsed_seconds = time.time() - self._start_time

    def _gather_from_environment(self) -> Iterator[GatheredSecret]:
        """Gather secrets from environment variables."""
        source = EnvironmentSecretSource()
        for secret in source.gather():
            if len(secret.value) >= self.config.min_chars:
                self._stats.env_vars_count += 1
                yield secret

        self._report_source_complete(
            SourceResult(
                source_type=SourceType.ENVIRONMENT_VAR,
                status=SourceStatus.COMPLETED,
                secrets_found=self._stats.env_vars_count,
            )
        )

    def _gather_from_github_cli(self) -> Iterator[GatheredSecret]:
        """Gather GitHub token from gh CLI."""
        source = GitHubTokenSource()
        for secret in source.gather():
            self._stats.github_token_found = True
            yield secret

        self._report_source_complete(
            SourceResult(
                source_type=SourceType.GITHUB_TOKEN,
                status=(
                    SourceStatus.COMPLETED
                    if self._stats.github_token_found
                    else SourceStatus.NOT_FOUND
                ),
                secrets_found=1 if self._stats.github_token_found else 0,
                message="found" if self._stats.github_token_found else "not found",
            )
        )

    def _gather_from_npmrc(self, home: Path) -> Iterator[GatheredSecret]:
        """Gather secrets from ~/.npmrc."""
        source = NpmrcSource(home_dir=home)
        secrets_found = 0
        for secret in source.gather():
            if len(secret.value) >= self.config.min_chars:
                secrets_found += 1
                yield secret

        if secrets_found > 0:
            self._stats.npmrc_files = 1
            self._stats.npmrc_secrets = secrets_found

        self._report_source_complete(
            SourceResult(
                source_type=SourceType.NPMRC,
                status=(
                    SourceStatus.COMPLETED
                    if secrets_found > 0
                    else SourceStatus.NOT_FOUND
                ),
                secrets_found=secrets_found,
                files_scanned=1 if secrets_found > 0 else 0,
                message=(
                    f"{secrets_found} secrets"
                    if secrets_found > 0
                    else "no .npmrc found"
                ),
            )
        )

    def _gather_from_env_files(self, home: Path) -> Iterator[GatheredSecret]:
        """Gather secrets from .env* files."""

        def on_source_progress(files_visited: int) -> None:
            self._stats.total_files_visited = files_visited
            self._report_progress_force("Scanning .env files")

        source = EnvFileSource(
            home_dir=home,
            timeout=self.config.timeout,
            min_chars=self.config.min_chars,
            is_timed_out=self._is_timed_out,
            on_progress=on_source_progress,
            exclusion_regexes=self.config.exclusion_regexes,
        )

        for secret in source.gather():
            # Update stats during iteration
            self._stats.total_files_visited = source.files_visited
            yield secret

        self._stats.env_files = source.files_found
        self._stats.env_secrets = source.secrets_found
        self._stats.total_files_visited = source.files_visited

        if self._is_timed_out():
            self._stats.timed_out = True

        self._report_source_complete(
            SourceResult(
                source_type=SourceType.ENV_FILE,
                status=SourceStatus.COMPLETED,
                secrets_found=source.secrets_found,
                files_scanned=source.files_found,
            )
        )

    def _gather_from_private_keys(self, home: Path) -> Iterator[GatheredSecret]:
        """Gather secrets from private key files."""
        # Track the baseline from env files scan
        baseline_files = self._stats.total_files_visited

        def on_source_progress(files_visited: int) -> None:
            self._stats.total_files_visited = baseline_files + files_visited
            self._report_progress_force("Scanning for private keys")

        source = PrivateKeySource(
            home_dir=home,
            timeout=self.config.timeout,
            is_timed_out=self._is_timed_out,
            on_progress=on_source_progress,
            exclusion_regexes=self.config.exclusion_regexes,
        )

        for secret in source.gather():
            # Update stats during iteration
            self._stats.total_files_visited = baseline_files + source.files_visited
            yield secret

        self._stats.private_key_files = source.files_found
        self._stats.private_key_secrets = source.secrets_found
        self._stats.total_files_visited = baseline_files + source.files_visited

        if self._is_timed_out():
            self._stats.timed_out = True

        self._report_source_complete(
            SourceResult(
                source_type=SourceType.PRIVATE_KEY,
                status=SourceStatus.COMPLETED,
                secrets_found=source.secrets_found,
                files_scanned=source.files_found,
            )
        )

    def _is_timed_out(self) -> bool:
        """Check if the gathering has exceeded the timeout."""
        if self.config.timeout <= 0:
            return False
        if self._start_time is None:
            return False
        return (time.time() - self._start_time) > self.config.timeout

    def _report_progress(self, phase: str) -> None:
        """Report progress if callback is set and enough files have been visited."""
        if self.config.on_progress is None:
            return

        # Only report every PROGRESS_INTERVAL files
        if (
            self._stats.total_files_visited - self._last_progress_files
            < self.PROGRESS_INTERVAL
        ):
            return

        self._last_progress_files = self._stats.total_files_visited
        elapsed = time.time() - (self._start_time or time.time())
        self.config.on_progress(phase, self._stats.total_files_visited, elapsed)

    def _report_progress_force(self, phase: str) -> None:
        """Report progress unconditionally (for phase changes)."""
        if self.config.on_progress is None:
            return

        elapsed = time.time() - (self._start_time or time.time())
        self.config.on_progress(phase, self._stats.total_files_visited, elapsed)

    def _report_source_complete(self, result: SourceResult) -> None:
        """Report that a source has completed scanning."""
        if self.config.on_source_complete is None:
            return

        self.config.on_source_complete(result)

    @property
    def stats(self) -> GatheringStats:
        """Return gathering statistics."""
        return self._stats
