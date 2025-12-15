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
        # Virtual/kernel filesystems
        "/proc",  # Kernel/process info
        "/sys",  # Sysfs - hardware/driver info
        "/dev",  # Device files
        "/run",  # Runtime data (PIDs, sockets)
        # Boot and system
        "/boot",  # Bootloader and kernel images
        "/lost+found",  # Filesystem recovery
        # Package managers
        "/snap",  # Snap package mounts
        # System libraries (no user secrets)
        "/usr/lib",  # System libraries
        "/usr/lib64",  # 64-bit libraries
        "/usr/lib32",  # 32-bit libraries
        "/usr/share",  # Shared data (docs, icons)
        "/usr/bin",  # System binaries
        "/usr/sbin",  # System admin binaries
        "/usr/include",  # Header files
        "/usr/src",  # Kernel source
        "/lib",  # Essential libraries (often symlink)
        "/lib64",  # 64-bit libraries (often symlink)
        "/lib32",  # 32-bit libraries (if present)
        # Variable/temp data
        "/var/cache",  # Package manager caches
        "/var/log",  # System log files
        "/var/tmp",  # Temporary files
        "/var/spool",  # Print/mail spools
        "/var/crash",  # Crash dumps
        "/tmp",  # Temporary files
        # Standard mount points (may contain user data but skip by default)
        "/mnt",  # Temporary mount points
        "/media",  # Removable media
        "/srv",  # Site-specific data served by system
        # Network filesystems (static - dynamic detection is primary)
        "/afs",  # Andrew File System
        # Container/VM runtime
        "/var/lib/docker",  # Docker images/containers
        "/var/lib/containers",  # Podman containers
        "/var/lib/lxc",  # LXC containers
        "/var/lib/libvirt",  # Libvirt VM storage
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


# Remote filesystem types to skip by default in full-disk mode
REMOTE_FS_TYPES = frozenset(
    {
        "nfs",
        "nfs4",  # Network File System
        "cifs",
        "smbfs",  # Windows/Samba shares
        "sshfs",  # SSH filesystem
        "fuse.sshfs",  # FUSE SSH filesystem
        "afs",  # Andrew File System
        "ncpfs",  # NetWare Core Protocol
        "9p",  # Plan 9 filesystem (common in VMs)
        "coda",  # Coda distributed filesystem
        "lustre",  # Lustre HPC filesystem
        "glusterfs",  # GlusterFS
        "fuse.glusterfs",  # FUSE GlusterFS
        "pvfs2",  # Parallel Virtual File System
        "gpfs",  # IBM Spectrum Scale
        "beegfs",  # BeeGFS parallel filesystem
    }
)


def get_remote_mount_points() -> frozenset:
    """Get mount points of remote/network filesystems on Linux.

    Parses /proc/mounts to find NFS, CIFS, SSHFS, and other remote mounts.
    Returns empty set on non-Linux or if /proc/mounts is unavailable.

    Returns:
        Frozenset of mount point paths for remote filesystems.
    """
    if not is_linux():
        return frozenset()

    try:
        with open("/proc/mounts", "r") as f:
            remote_mounts = set()
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    mount_point, fs_type = parts[1], parts[2]
                    if fs_type in REMOTE_FS_TYPES:
                        remote_mounts.add(mount_point)
            return frozenset(remote_mounts)
    except (OSError, IOError):
        return frozenset()


# Progress update interval in seconds
PROGRESS_INTERVAL_SECONDS = 0.2


@dataclass
class WalkerStats:
    """Statistics from the unified walk."""

    files_visited: int = 0
    matches_by_type: Dict[SourceType, int] = field(default_factory=dict)
    secrets_by_type: Dict[SourceType, int] = field(default_factory=dict)
    # Paths that couldn't be accessed due to permission errors
    permission_denied_paths: List[str] = field(default_factory=list)


# Type for progress callback: (files_visited, matches_by_type, current_dir) -> None
WalkerProgressCallback = Callable[[int, Dict[SourceType, int], str], None]

# Type for candidate file callback: (file_path) -> None
CandidateFileCallback = Callable[[Path], None]

# Type for permission denied callback: (file_path) -> None
PermissionDeniedCallback = Callable[[str], None]

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
    # Include remote/network filesystems (NFS, CIFS, etc.) in full-disk scan
    # By default, remote mounts are skipped to avoid scanning large network storage
    include_remote_mounts: bool = False


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
        self._current_root = ""  # Track current directory for progress reporting

        # Merge default exclusions with user-provided ones
        self._all_exclusion_regexes: Set[Pattern[str]] = set(config.exclusion_regexes)
        self._all_exclusion_regexes.update(get_default_exclusion_regexes())

        # Cache platform-specific exclusions if in full-disk mode
        self._full_disk_exclusions = (
            get_full_disk_exclusions() if config.full_disk_mode else frozenset()
        )

        # Cache remote mount points if NOT including them (full-disk mode only)
        # On non-Linux, this returns empty set (macOS uses /Volumes exclusion instead)
        self._remote_mounts: frozenset = (
            frozenset()
            if config.include_remote_mounts or not config.full_disk_mode
            else get_remote_mount_points()
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

        def on_walk_error(error: OSError) -> None:
            """Handle permission errors during directory traversal."""
            if isinstance(error, PermissionError):
                self._stats.permission_denied_paths.append(error.filename or str(error))

        for root, dirs, files in os.walk(
            self.config.home_dir, onerror=on_walk_error
        ):
            self._stats.files_visited += len(files)
            self._current_root = root  # Track for progress reporting

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

        In full-disk mode, also excludes:
        - Platform-specific system directories
        - Remote/network mounts (NFS, CIFS, etc.) unless include_remote_mounts is set

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

            # Build full path for subsequent checks
            full_path = os.path.join(current_root, dirname)

            # Check full-disk exclusions if enabled
            if self._full_disk_exclusions:
                # Check if full path matches any exclusion (for absolute paths like /proc)
                if full_path in self._full_disk_exclusions:
                    indices_to_remove.append(i)
                    continue

                # Check if directory name matches any exclusion (for relative names like "Windows")
                if dirname in self._full_disk_exclusions:
                    indices_to_remove.append(i)
                    continue

            # Check remote mount exclusions (detected dynamically from /proc/mounts)
            if self._remote_mounts and full_path in self._remote_mounts:
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
                self._current_root,
            )

    @property
    def stats(self) -> WalkerStats:
        """Return walker statistics."""
        return self._stats
