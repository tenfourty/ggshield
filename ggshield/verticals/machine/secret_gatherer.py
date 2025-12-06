"""
Main secret gathering orchestrator for machine scanning.
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, Iterator, Optional, Pattern, Set

from ggshield.utils.files import is_path_excluded
from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)
from ggshield.verticals.machine.sources.environment import EnvironmentSecretSource
from ggshield.verticals.machine.sources.file_matcher import (
    EnvFileMatcher,
    PrivateKeyMatcher,
    _looks_like_key_content,
)
from ggshield.verticals.machine.sources.github_token import GitHubTokenSource
from ggshield.verticals.machine.sources.npmrc import NpmrcSource
from ggshield.verticals.machine.sources.unified_walker import (
    UnifiedFileSystemWalker,
    WalkerConfig,
)


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

        # Filesystem sources (single unified traversal, respects timeout)
        if not self._is_timed_out():
            yield from self._gather_from_filesystem(home)

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

    def _gather_from_filesystem(self, home: Path) -> Iterator[GatheredSecret]:
        """
        Gather secrets from filesystem using single unified traversal.

        Scans well-known key locations first (fast-path), then performs
        a single os.walk() traversal for all file types.
        """
        # Track private keys already seen in well-known locations
        seen_key_paths: Set[Path] = set()

        # Fast-path: scan well-known private key locations first
        # This ensures we find important keys even if timeout hits during full scan
        yield from self._scan_well_known_key_locations(home, seen_key_paths)

        if self._is_timed_out():
            self._finalize_filesystem_stats(0, {}, {})
            return

        # Create matchers for unified walk
        env_matcher = EnvFileMatcher(min_chars=self.config.min_chars)
        key_matcher = PrivateKeyMatcher(seen_paths=seen_key_paths)

        def on_walker_progress(
            files_visited: int, matches_by_type: Dict[SourceType, int]
        ) -> None:
            self._stats.total_files_visited = files_visited
            self._report_progress_with_counts(files_visited, matches_by_type)

        walker_config = WalkerConfig(
            home_dir=home,
            matchers=[env_matcher, key_matcher],
            is_timed_out=self._is_timed_out,
            exclusion_regexes=self.config.exclusion_regexes,
            on_progress=on_walker_progress,
        )

        walker = UnifiedFileSystemWalker(walker_config)

        # Single filesystem traversal
        self._report_progress_force("Scanning home directory")
        for secret in walker.walk():
            self._stats.total_files_visited = walker.stats.files_visited
            yield secret

        if self._is_timed_out():
            self._stats.timed_out = True

        # Finalize stats from walker
        self._finalize_filesystem_stats(
            walker.stats.files_visited,
            walker.stats.matches_by_type,
            walker.stats.secrets_by_type,
        )

    def _scan_well_known_key_locations(
        self, home: Path, seen_paths: Set[Path]
    ) -> Iterator[GatheredSecret]:
        """
        Scan well-known locations for private keys (fast-path).

        This is done before the full filesystem scan to ensure important
        keys are found even if timeout hits during the full walk.
        """
        well_known_dirs = [
            home / ".ssh",
            home / ".gnupg",
            home / ".ssl",
            home / ".certs",
        ]

        # Maximum file size for private keys (10KB)
        max_key_size = 10 * 1024

        for key_dir in well_known_dirs:
            if not key_dir.exists() or not key_dir.is_dir():
                continue

            try:
                for fpath in key_dir.iterdir():
                    if self._is_timed_out():
                        return

                    if not fpath.is_file():
                        continue

                    # Check exclusion patterns
                    if is_path_excluded(fpath, self.config.exclusion_regexes):
                        continue

                    # Check file size
                    try:
                        stat = fpath.stat()
                        if stat.st_size > max_key_size:
                            continue
                    except (OSError, PermissionError):
                        continue

                    # Read and validate content
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="ignore")
                    except (OSError, PermissionError):
                        continue

                    if not content.strip():
                        continue

                    if not _looks_like_key_content(content):
                        continue

                    # Mark as seen to avoid duplicates in full scan
                    seen_paths.add(fpath)

                    self._stats.private_key_files += 1
                    self._stats.private_key_secrets += 1

                    yield GatheredSecret(
                        value=content.strip(),
                        metadata=SecretMetadata(
                            source_type=SourceType.PRIVATE_KEY,
                            source_path=str(fpath),
                            secret_name=fpath.name,
                        ),
                    )
            except (OSError, PermissionError):
                continue

    def _finalize_filesystem_stats(
        self,
        files_visited: int,
        matches_by_type: Dict[SourceType, int],
        secrets_by_type: Dict[SourceType, int],
    ) -> None:
        """Update stats and report completion for filesystem sources."""
        self._stats.total_files_visited = files_visited

        # Env files stats (from walker only)
        env_files = matches_by_type.get(SourceType.ENV_FILE, 0)
        env_secrets = secrets_by_type.get(SourceType.ENV_FILE, 0)
        self._stats.env_files = env_files
        self._stats.env_secrets = env_secrets

        # Private key stats (well-known + walker)
        key_files_from_walker = matches_by_type.get(SourceType.PRIVATE_KEY, 0)
        key_secrets_from_walker = secrets_by_type.get(SourceType.PRIVATE_KEY, 0)
        self._stats.private_key_files += key_files_from_walker
        self._stats.private_key_secrets += key_secrets_from_walker

        # Report env files completion
        self._report_source_complete(
            SourceResult(
                source_type=SourceType.ENV_FILE,
                status=SourceStatus.COMPLETED,
                secrets_found=env_secrets,
                files_scanned=env_files,
            )
        )

        # Report private keys completion
        self._report_source_complete(
            SourceResult(
                source_type=SourceType.PRIVATE_KEY,
                status=SourceStatus.COMPLETED,
                secrets_found=self._stats.private_key_secrets,
                files_scanned=self._stats.private_key_files,
            )
        )

    def _report_progress_with_counts(
        self, files_visited: int, matches_by_type: Dict[SourceType, int]
    ) -> None:
        """Report progress with per-type match counts."""
        if self.config.on_progress is None:
            return

        elapsed = time.time() - (self._start_time or time.time())
        # Pass phase with counts embedded for display
        env_count = matches_by_type.get(SourceType.ENV_FILE, 0)
        key_count = matches_by_type.get(SourceType.PRIVATE_KEY, 0)
        phase = f"Scanning home directory | .env: {env_count} | keys: {key_count}"
        self.config.on_progress(phase, files_visited, elapsed)

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
