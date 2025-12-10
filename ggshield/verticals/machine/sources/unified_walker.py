"""
Unified filesystem walker for single-pass secret scanning.

This module provides a single os.walk() traversal that dispatches files
to multiple FileMatcher implementations, eliminating duplicate filesystem scans.
"""

import os
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Pattern, Set

from ggshield.core.filter import init_exclusion_regexes
from ggshield.utils.files import is_path_excluded
from ggshield.verticals.machine.sources import GatheredSecret, SourceType
from ggshield.verticals.machine.sources.file_matcher import FileMatcher
from ggshield.verticals.machine.sources.platform_paths import (
    is_linux,
    is_macos,
    is_windows,
)


# Directories to ignore during traversal (ignore-list approach for comprehensive scanning)
IGNORED_DIRECTORIES = {
    # Version control
    ".git",
    ".hg",
    ".svn",
    # Package managers / dependencies
    "node_modules",
    ".npm",
    ".yarn",
    ".pnpm-store",
    # Python
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".eggs",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    # Build outputs
    "dist",
    "build",
    "target",
    "_build",
    # Caches (typically large, low value) - macOS
    ".cache",
    ".local/share/Trash",
    ".Trash",
    "Library/Caches",
    # Caches - Windows (under user home, e.g., C:\Users\<user>\AppData)
    "AppData/Local/Temp",
    "AppData/Local/Microsoft/Windows/INetCache",
    "AppData/Local/pip/cache",
    # Application caches with low credential value
    ".gradle/caches",
    ".m2/repository",
    ".cargo/registry",
    ".rustup",
    # IDE/editor state
    ".idea",
    ".vscode",
    ".vs",
    # Logs
    "logs",
    ".logs",
}

# Path patterns to exclude (matched against full path)
# These are converted to regexes and applied in addition to user-provided exclusions.
# IMPORTANT: Patterns ending with "/" match as prefixes (no $ anchor), allowing them
# to match all files under that path. Patterns ending with "**" don't work correctly
# because translate_user_pattern() converts them to ([^/]+)([^/]+) which only matches
# exactly 2 path segments.
DEFAULT_EXCLUSION_PATTERNS = {
    # Apple Wallet passes (any OS) - authenticationToken is provider-generated,
    # not a user credential. Used for pass updates, not account access.
    "**/*.pkpass/",
    # App update framework caches (macOS)
    "**/org.sparkle-project.Sparkle/",
    # Package manager caches and source directories
    "**/.bun/install/cache/",
    # Rust crate source cache - extracted third-party crate sources
    # See: https://doc.rust-lang.org/cargo/guide/cargo-home.html
    "**/.cargo/registry/src/",
    # Python installed packages - third-party libs that may contain test data
    # See: https://docs.python.org/3/library/site.html
    "**/site-packages/",
    # Test directories - contain test fixtures, not real secrets
    "**/tests/",
    # SDKs with example/test data
    "**/google-cloud-sdk/",
    # Files handled by dedicated sources (avoid duplicate detection in deep scan)
    # These sources extract specific tokens; deep scan would find generic entropy
    "**/.config/raycast/config.json",
    "**/.config/joplin-desktop/settings.json",
    "**/.factory/auth.json",
    "**/.gemini/oauth_creds.json",
    # Claude Code app preferences - contains session IDs, not credentials
    "**/.claude.json",
    # AMP IDE local session tokens - auto-generated per workspace, local-only
    "**/.local/share/amp/ide/",
    # Chromium-based browser extension declarativeNetRequest rules - extension config, not credentials
    # Applies to Chrome, Edge, Brave, Comet, Arc, and other Chromium browsers
    # See: https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest
    "**/DNR Extension Rules/",
    # Apple iCloud/CloudKit sync data - binary plists, not user credentials
    "**/group.com.apple.stocks/",
    "**/com.apple.siri.findmy/",
    # 1Password internal settings - high-entropy app config, not user secrets
    # 2BUA8C4S2C is AgileBits' Apple Team ID, same for all 1Password users
    "**/2BUA8C4S2C.com.1password/",
    # Firefox addons.json - contains addon metadata (names, versions, store URLs), not credentials
    # amoListingURL field triggers false positive "Generic Password" detection
    "**/Firefox/Profiles/*/addons.json",
}


@lru_cache(maxsize=1)
def get_default_exclusion_regexes() -> frozenset:
    """Get compiled regex patterns for default exclusions (cached)."""
    return frozenset(init_exclusion_regexes(DEFAULT_EXCLUSION_PATTERNS))


# Platform-specific directories to exclude in full-disk mode
# These are system directories that don't contain user secrets

FULL_DISK_EXCLUSIONS_LINUX = frozenset(
    {
        "/proc",  # Virtual filesystem - kernel/process info
        "/sys",  # Kernel sysfs - hardware/driver info
        "/dev",  # Device files
        "/run",  # Runtime data (PIDs, sockets)
        "/boot",  # Bootloader and kernel images
        "/snap",  # Snap package mounts
        "/var/cache",  # Package manager caches
        "/var/log",  # System log files
        "/var/tmp",  # Temporary files
        "/usr/lib",  # System libraries
        "/usr/share",  # Shared data (docs, icons)
        "/lib",  # Essential libraries
        "/lib64",  # 64-bit libraries
        "/lib32",  # 32-bit libraries (if present)
        "/lost+found",  # Filesystem recovery
    }
)

FULL_DISK_EXCLUSIONS_WINDOWS = frozenset(
    {
        # Note: These are directory names, not full paths, for simpler matching
        "Windows",  # C:\Windows
        "Program Files",  # C:\Program Files
        "Program Files (x86)",  # C:\Program Files (x86)
        "System Volume Information",  # Restore points
        "$Recycle.Bin",  # Recycle bin
        "PerfLogs",  # Performance logs
        "Recovery",  # System recovery
        "$WinREAgent",  # Windows Recovery Agent
        "$SysReset",  # System reset data
    }
)

FULL_DISK_EXCLUSIONS_MACOS = frozenset(
    {
        "/System",  # macOS system files (SIP protected)
        "/Library/Caches",  # System-wide caches
        "/private/var/folders",  # Temporary caches
        "/private/var/log",  # System logs
        "/private/var/db",  # System databases
        "/Volumes",  # Other mounted volumes (avoid recursive mounts)
        "/cores",  # Core dumps
        ".Spotlight-V100",  # Spotlight index
        ".fseventsd",  # FSEvents data
        ".Trashes",  # Trash directories
        ".DocumentRevisions-V100",  # Document versioning
        ".TemporaryItems",  # Temporary items
    }
)


def get_full_disk_exclusions() -> frozenset:
    """Get platform-specific exclusions for full-disk scanning.

    Returns:
        Set of directory paths/names to exclude during full-disk scans.
    """
    if is_macos():
        return FULL_DISK_EXCLUSIONS_MACOS
    elif is_windows():
        return FULL_DISK_EXCLUSIONS_WINDOWS
    elif is_linux():
        return FULL_DISK_EXCLUSIONS_LINUX
    return frozenset()


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

# Type for candidate file callback: (file_path) -> None
CandidateFileCallback = Callable[[Path], None]

# File extensions that are candidates for deep scan (text-based config files)
DEEP_SCAN_EXTENSIONS = frozenset(
    {
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".conf",
        ".cfg",
        ".properties",
        ".xml",
    }
)


@dataclass
class WalkerConfig:
    """Configuration for the unified filesystem walker."""

    home_dir: Path
    matchers: List[FileMatcher]
    is_timed_out: Callable[[], bool]
    exclusion_regexes: Set[Pattern[str]] = field(default_factory=set)
    on_progress: Optional[WalkerProgressCallback] = None
    # Callback for collecting files for deep scan (API-based scanning)
    on_candidate_file: Optional[CandidateFileCallback] = None
    # Enable platform-specific exclusions for full-disk scanning
    full_disk_mode: bool = False


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

        # Merge default exclusions with user-provided ones
        self._all_exclusion_regexes: Set[Pattern[str]] = set(config.exclusion_regexes)
        self._all_exclusion_regexes.update(get_default_exclusion_regexes())

        # Cache platform-specific exclusions if in full-disk mode
        self._full_disk_exclusions = (
            get_full_disk_exclusions() if config.full_disk_mode else frozenset()
        )

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
            self._prune_directories(dirs, root)

            # Process files with string-based matching first (PERF: no Path creation)
            for filename in files:
                matched = False

                # Find first matcher that matches this filename
                for matcher in self.config.matchers:
                    if matcher.matches_filename(filename):
                        # Only create Path for matched files
                        file_path = Path(root) / filename

                        # Extract secrets and track stats
                        # Track secrets count separately from file matches
                        secrets_from_file = 0
                        for secret in matcher.extract_secrets(
                            file_path, self._all_exclusion_regexes
                        ):
                            secrets_from_file += 1
                            self._stats.secrets_by_type[matcher.source_type] += 1
                            yield secret

                        # Only count as matched file if we found secrets
                        if secrets_from_file > 0:
                            self._stats.matches_by_type[matcher.source_type] += 1

                        # First matcher wins (no double-extraction)
                        matched = True
                        break

                # If not matched by dedicated matchers, check for deep scan candidate
                if not matched and self.config.on_candidate_file is not None:
                    suffix = Path(filename).suffix.lower()
                    if suffix in DEEP_SCAN_EXTENSIONS:
                        file_path = Path(root) / filename
                        # Apply exclusion patterns to deep scan candidates
                        if not is_path_excluded(file_path, self._all_exclusion_regexes):
                            self.config.on_candidate_file(file_path)

    def _prune_directories(self, dirs: List[str], current_root: str = "") -> None:
        """
        Remove directories we should skip from the traversal list.

        Modifies dirs in-place to prevent os.walk from descending
        into unwanted directories.

        Uses an ignore-list approach - all directories are scanned EXCEPT those
        explicitly listed in IGNORED_DIRECTORIES. This ensures comprehensive
        coverage of hidden directories that may contain credentials.

        In full-disk mode, also excludes platform-specific system directories.

        Args:
            dirs: List of directory names to filter (modified in-place)
            current_root: Current directory path (for building full paths)
        """
        indices_to_remove = []

        for i, dirname in enumerate(dirs):
            # Check standard ignored directories (by name)
            if dirname in IGNORED_DIRECTORIES:
                indices_to_remove.append(i)
                continue

            # Check full-disk exclusions if enabled
            if self._full_disk_exclusions:
                # Build full path to check against absolute path exclusions
                full_path = os.path.join(current_root, dirname)

                # Check if full path matches any exclusion (for absolute paths like /proc)
                if full_path in self._full_disk_exclusions:
                    indices_to_remove.append(i)
                    continue

                # Check if directory name matches any exclusion (for relative names like "Windows")
                if dirname in self._full_disk_exclusions:
                    indices_to_remove.append(i)
                    continue

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
