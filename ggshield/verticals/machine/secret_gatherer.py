"""
Main secret gathering orchestrator for machine scanning.
"""

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    Pattern,
    Set,
    Type,
)

from ggshield.utils.files import is_path_excluded
from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)


if TYPE_CHECKING:
    from pygitguardian import GGClient

from ggshield.verticals.machine.sources.aider_config import AiderConfigSource
from ggshield.verticals.machine.sources.aws_credentials import AwsCredentialsSource
from ggshield.verticals.machine.sources.azure_cli import AzureCliSource
from ggshield.verticals.machine.sources.base import SecretSource
from ggshield.verticals.machine.sources.cargo_credentials import CargoCredentialsSource
from ggshield.verticals.machine.sources.circleci_config import CircleCIConfigSource
from ggshield.verticals.machine.sources.claude_code import ClaudeCodeSource
from ggshield.verticals.machine.sources.composer_auth import ComposerAuthSource
from ggshield.verticals.machine.sources.continue_config import ContinueConfigSource
from ggshield.verticals.machine.sources.docker_config import DockerConfigSource
from ggshield.verticals.machine.sources.environment import EnvironmentSecretSource
from ggshield.verticals.machine.sources.factory_auth import FactoryAuthSource
from ggshield.verticals.machine.sources.file_matcher import (
    EnvFileMatcher,
    PrivateKeyMatcher,
    _looks_like_key_content,
)
from ggshield.verticals.machine.sources.gcp_adc import GcpAdcSource
from ggshield.verticals.machine.sources.gem_credentials import GemCredentialsSource
from ggshield.verticals.machine.sources.gemini_cli import GeminiCliSource
from ggshield.verticals.machine.sources.git_credentials import GitCredentialsSource
from ggshield.verticals.machine.sources.github_token import GitHubTokenSource
from ggshield.verticals.machine.sources.gitlab_cli import GitLabCliSource
from ggshield.verticals.machine.sources.gradle_properties import GradlePropertiesSource
from ggshield.verticals.machine.sources.helm_config import HelmConfigSource
from ggshield.verticals.machine.sources.joplin_config import JoplinConfigSource
from ggshield.verticals.machine.sources.kubernetes_config import KubernetesConfigSource
from ggshield.verticals.machine.sources.mysql_config import MysqlConfigSource
from ggshield.verticals.machine.sources.netrc import NetrcSource
from ggshield.verticals.machine.sources.npmrc import NpmrcSource
from ggshield.verticals.machine.sources.pgpass import PgpassSource
from ggshield.verticals.machine.sources.pypirc import PypircSource

# Desktop apps
from ggshield.verticals.machine.sources.raycast_config import RaycastConfigSource
from ggshield.verticals.machine.sources.slack_credentials import SlackCredentialsSource
from ggshield.verticals.machine.sources.travis_ci_config import TravisCIConfigSource
from ggshield.verticals.machine.sources.unified_walker import (
    UnifiedFileSystemWalker,
    WalkerConfig,
)
from ggshield.verticals.machine.sources.vault_token import VaultTokenSource


# Credential file sources - single-file reads that can use the generic gatherer
# Each source class must accept home_dir as a keyword argument
CREDENTIAL_FILE_SOURCES: List[Type[SecretSource]] = [
    # Cloud providers
    AwsCredentialsSource,
    GcpAdcSource,
    AzureCliSource,
    KubernetesConfigSource,
    # Container registries
    DockerConfigSource,
    # Package registries
    PypircSource,
    CargoCredentialsSource,
    GemCredentialsSource,
    ComposerAuthSource,
    HelmConfigSource,
    GradlePropertiesSource,
    # CI/CD platforms
    CircleCIConfigSource,
    GitLabCliSource,
    TravisCIConfigSource,
    # Other credential files
    VaultTokenSource,
    NetrcSource,
    GitCredentialsSource,
    # Databases
    PgpassSource,
    MysqlConfigSource,
    # AI coding tools
    ClaudeCodeSource,
    GeminiCliSource,
    AiderConfigSource,
    ContinueConfigSource,
    # Messaging
    SlackCredentialsSource,
    # Desktop apps
    RaycastConfigSource,
    JoplinConfigSource,
    FactoryAuthSource,
]


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
    # For DEEP_SCAN: breakdown of secrets by detector type
    detector_counts: Optional[Dict[str, int]] = None


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
    # Deep scan settings (API-based comprehensive scanning)
    deep_scan: bool = False
    client: Optional["GGClient"] = field(default=None, repr=False)


@dataclass
class GatheringStats:
    """Statistics from the gathering process."""

    # Per-source secret counts (replaces individual fields)
    source_counts: Dict[SourceType, int] = field(default_factory=dict)

    # File counts for sources that scan multiple files
    file_counts: Dict[SourceType, int] = field(default_factory=dict)

    # Special boolean flags for single-item sources
    github_token_found: bool = False
    vault_token_found: bool = False

    # Deep scan stats (kept separate as they have different semantics)
    deep_scan_files: int = 0
    deep_scan_secrets: int = 0
    deep_scan_skipped: int = 0

    # Totals
    total_files_visited: int = 0
    elapsed_seconds: float = 0.0
    timed_out: bool = False

    def increment_secrets(self, source_type: SourceType, count: int = 1) -> None:
        """Increment secret count for a source type."""
        self.source_counts[source_type] = self.source_counts.get(source_type, 0) + count

    def increment_files(self, source_type: SourceType, count: int = 1) -> None:
        """Increment file count for a source type."""
        self.file_counts[source_type] = self.file_counts.get(source_type, 0) + count

    def get_secrets(self, source_type: SourceType) -> int:
        """Get secret count for a source type."""
        return self.source_counts.get(source_type, 0)

    def get_files(self, source_type: SourceType) -> int:
        """Get file count for a source type."""
        return self.file_counts.get(source_type, 0)


class MachineSecretGatherer:
    """
    Gathers secrets from various machine sources.

    Uses a streaming approach - yields secrets as they're found
    without storing them to disk.

    When deep_scan is enabled, also collects candidate files during
    filesystem traversal and sends them to the GitGuardian API for
    comprehensive scanning with 500+ detectors.
    """

    # Report progress every N files visited
    PROGRESS_INTERVAL = 10000

    def __init__(self, config: GatheringConfig):
        self.config = config
        self._stats = GatheringStats()
        self._start_time: Optional[float] = None
        self._last_progress_files: int = 0
        # Content-hash deduplication (SHA256 of secret values)
        self._seen_secret_hashes: Set[str] = set()
        # Files to scan via API (for deep scan mode)
        self._candidate_files: List[Path] = []

    def _gather_from_source(
        self,
        source: SecretSource,
    ) -> Iterator[GatheredSecret]:
        """
        Generic source gathering with stats tracking.

        This method handles the common pattern for single-file credential sources:
        - Iterate secrets from the source
        - Filter by min_chars
        - Track stats
        - Report completion

        Args:
            source: The secret source to gather from

        Yields:
            GatheredSecret instances that meet the min_chars threshold
        """
        secrets_found = 0
        for secret in source.gather():
            if len(secret.value) >= self.config.min_chars:
                secrets_found += 1
                self._stats.increment_secrets(source.source_type)
                yield secret

        self._report_source_complete(
            SourceResult(
                source_type=source.source_type,
                status=(
                    SourceStatus.COMPLETED
                    if secrets_found > 0
                    else SourceStatus.NOT_FOUND
                ),
                secrets_found=secrets_found,
            )
        )

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Gather secrets from all configured sources.

        Yields secrets as they're discovered. Statistics are
        updated incrementally and available via `stats` property.

        When deep_scan is enabled, also sends candidate files to the
        GitGuardian API for comprehensive scanning. Secrets are deduplicated
        by content hash to ensure dedicated sources take priority.
        """
        self._start_time = time.time()
        self._stats = GatheringStats()
        self._seen_secret_hashes.clear()
        self._candidate_files.clear()

        home = self.config.home_dir or Path.home()

        # Fast sources first (special handling required)
        yield from self._gather_from_environment()
        yield from self._gather_from_github_cli()
        yield from self._gather_from_npmrc(home)

        # Credential file sources (single-file reads via generic gatherer)
        for source_cls in CREDENTIAL_FILE_SOURCES:
            yield from self._gather_from_source(source_cls(home_dir=home))

        # Filesystem sources (single unified traversal, respects timeout)
        if not self._is_timed_out():
            yield from self._gather_from_filesystem(home)

        # Deep scan phase (API-based comprehensive scanning)
        if self.config.deep_scan and self.config.client and not self._is_timed_out():
            yield from self._gather_from_deep_scan()

        self._stats.elapsed_seconds = time.time() - self._start_time

    def _gather_from_environment(self) -> Iterator[GatheredSecret]:
        """Gather secrets from environment variables."""
        source = EnvironmentSecretSource()
        secrets_found = 0
        for secret in source.gather():
            if len(secret.value) >= self.config.min_chars:
                secrets_found += 1
                self._stats.increment_secrets(SourceType.ENVIRONMENT_VAR)
                yield secret

        self._report_source_complete(
            SourceResult(
                source_type=SourceType.ENVIRONMENT_VAR,
                status=SourceStatus.COMPLETED,
                secrets_found=secrets_found,
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
                self._stats.increment_secrets(SourceType.NPMRC)
                yield secret

        if secrets_found > 0:
            self._stats.increment_files(SourceType.NPMRC)

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

        # Callback for collecting candidate files for deep scan
        on_candidate = self._add_candidate_file if self.config.deep_scan else None

        walker_config = WalkerConfig(
            home_dir=home,
            matchers=[env_matcher, key_matcher],
            is_timed_out=self._is_timed_out,
            exclusion_regexes=self.config.exclusion_regexes,
            on_progress=on_walker_progress,
            on_candidate_file=on_candidate,
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

                    self._stats.increment_files(SourceType.PRIVATE_KEY)
                    self._stats.increment_secrets(SourceType.PRIVATE_KEY)

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
        self._stats.increment_files(SourceType.ENV_FILE, env_files)
        self._stats.increment_secrets(SourceType.ENV_FILE, env_secrets)

        # Private key stats (well-known locations already counted, add walker results)
        key_files_from_walker = matches_by_type.get(SourceType.PRIVATE_KEY, 0)
        key_secrets_from_walker = secrets_by_type.get(SourceType.PRIVATE_KEY, 0)
        self._stats.increment_files(SourceType.PRIVATE_KEY, key_files_from_walker)
        self._stats.increment_secrets(SourceType.PRIVATE_KEY, key_secrets_from_walker)

        # Report env files completion
        self._report_source_complete(
            SourceResult(
                source_type=SourceType.ENV_FILE,
                status=SourceStatus.COMPLETED,
                secrets_found=self._stats.get_secrets(SourceType.ENV_FILE),
                files_scanned=self._stats.get_files(SourceType.ENV_FILE),
            )
        )

        # Report private keys completion
        self._report_source_complete(
            SourceResult(
                source_type=SourceType.PRIVATE_KEY,
                status=SourceStatus.COMPLETED,
                secrets_found=self._stats.get_secrets(SourceType.PRIVATE_KEY),
                files_scanned=self._stats.get_files(SourceType.PRIVATE_KEY),
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

    def _is_duplicate_secret(self, secret_value: str) -> bool:
        """
        Check if a secret value has already been seen.

        Uses SHA256 hash for efficient comparison without storing actual values.

        Args:
            secret_value: The secret value to check

        Returns:
            True if this secret has been seen before
        """
        secret_hash = hashlib.sha256(secret_value.encode()).hexdigest()
        if secret_hash in self._seen_secret_hashes:
            return True
        self._seen_secret_hashes.add(secret_hash)
        return False

    def _gather_from_deep_scan(self) -> Iterator[GatheredSecret]:
        """
        Gather secrets via GitGuardian API deep scan.

        Sends collected candidate files to the API for comprehensive
        scanning with 500+ detectors. Results are deduplicated against
        secrets already found by dedicated sources.
        """
        if not self._candidate_files or not self.config.client:
            return

        # Import here to avoid circular imports
        from ggshield.verticals.machine.deep_scanner import DeepFileScanner

        self._report_progress_force(
            f"Deep scanning {len(self._candidate_files)} files via API"
        )

        scanner = DeepFileScanner(self.config.client)

        def on_deep_scan_progress(files_scanned: int, total: int) -> None:
            self._report_progress_force(
                f"Deep scanning files via API ({files_scanned}/{total})"
            )

        result = scanner.scan_files(
            self._candidate_files, on_progress=on_deep_scan_progress
        )

        # Update stats
        self._stats.deep_scan_files = result.files_scanned
        self._stats.deep_scan_skipped = result.files_skipped

        # Collect detector counts and yield secrets with deduplication
        detector_counts: Dict[str, int] = {}
        for secret in result.secrets:
            if not self._is_duplicate_secret(secret.value):
                self._stats.deep_scan_secrets += 1
                # Count by detector type (stored in secret_name)
                detector_type = secret.metadata.secret_name
                detector_counts[detector_type] = (
                    detector_counts.get(detector_type, 0) + 1
                )
                yield secret

        # Report completion with detector breakdown
        self._report_source_complete(
            SourceResult(
                source_type=SourceType.DEEP_SCAN,
                status=SourceStatus.COMPLETED,
                secrets_found=self._stats.deep_scan_secrets,
                files_scanned=result.files_scanned,
                detector_counts=detector_counts if detector_counts else None,
            )
        )

    def _add_candidate_file(self, file_path: Path) -> None:
        """
        Add a file to the candidate list for deep scanning.

        Called during filesystem traversal for files that match
        deep scan extensions.

        Args:
            file_path: Path to add to candidate list
        """
        if self.config.deep_scan:
            self._candidate_files.append(file_path)
