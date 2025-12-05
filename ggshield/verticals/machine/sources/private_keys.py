"""
Private key file secret source.
"""

import os
from pathlib import Path
from typing import Callable, Iterator, Optional, Pattern, Set

from ggshield.utils.files import is_path_excluded
from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)
from ggshield.verticals.machine.sources.base import SecretSource


# Filenames that are typically private keys
PRIVATE_KEY_FILENAMES = {
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_xmss",
    "private_key",
    "privkey",
}

# File extensions for private keys
PRIVATE_KEY_EXTENSIONS = {
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".gpg",
    ".asc",
}

# Directories to skip during traversal
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

# Directories that start with . but should NOT be skipped
ALLOWED_DOT_DIRECTORIES = {".ssh", ".gnupg", ".aws", ".config", ".ssl", ".certs"}

# Maximum file size to process (10KB) - private keys are small
MAX_KEY_FILE_SIZE = 10 * 1024


# Type for progress callback: (files_visited) -> None
ProgressCallback = Callable[[int], None]

# Progress update interval in seconds
PROGRESS_INTERVAL_SECONDS = 0.2


class PrivateKeySource(SecretSource):
    """
    Collects secrets from private key files.

    Scans common locations for SSH keys, SSL certificates, and other
    cryptographic private key files.
    """

    def __init__(
        self,
        home_dir: Optional[Path] = None,
        timeout: int = 0,
        is_timed_out: Optional[Callable[[], bool]] = None,
        on_progress: Optional[ProgressCallback] = None,
        exclusion_regexes: Optional[Set[Pattern[str]]] = None,
    ):
        """
        Initialize private key source.

        Args:
            home_dir: Home directory to scan. Defaults to user's home.
            timeout: Timeout in seconds (0 = no timeout). Used for stats only.
            is_timed_out: Callback to check if scan has timed out.
            on_progress: Callback to report progress (receives files_visited).
            exclusion_regexes: Patterns for paths to exclude (from config).
        """
        self._home_dir = home_dir or Path.home()
        self._timeout = timeout
        self._is_timed_out = is_timed_out or (lambda: False)
        self._on_progress = on_progress
        self._exclusion_regexes = exclusion_regexes or set()
        self._last_progress_time = 0.0
        self.files_found = 0
        self.secrets_found = 0
        self.files_visited = 0

    @property
    def source_type(self) -> SourceType:
        return SourceType.PRIVATE_KEY

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from private key files.

        First scans well-known locations (~/.ssh, ~/.gnupg), then
        optionally does a broader scan if time permits.
        """
        seen_paths: Set[Path] = set()

        # Scan well-known key locations first (fast)
        yield from self._scan_well_known_locations(seen_paths)

        if self._is_timed_out():
            return

        # Then do broader home directory scan
        yield from self._scan_home_directory(seen_paths)

    def _scan_well_known_locations(
        self, seen_paths: Set[Path]
    ) -> Iterator[GatheredSecret]:
        """Scan well-known locations for private keys."""
        well_known_dirs = [
            self._home_dir / ".ssh",
            self._home_dir / ".gnupg",
            self._home_dir / ".ssl",
            self._home_dir / ".certs",
        ]

        for key_dir in well_known_dirs:
            if not key_dir.exists() or not key_dir.is_dir():
                continue

            try:
                for fpath in key_dir.iterdir():
                    if self._is_timed_out():
                        return

                    if fpath.is_file() and self._is_private_key_file(fpath):
                        # Skip files matching exclusion patterns from config
                        if is_path_excluded(fpath, self._exclusion_regexes):
                            continue
                        seen_paths.add(fpath)
                        yield from self._extract_key_from_file(fpath)
            except (OSError, PermissionError):
                continue

    def _scan_home_directory(self, seen_paths: Set[Path]) -> Iterator[GatheredSecret]:
        """Scan home directory for private key files."""
        import time

        for root, dirs, files in os.walk(self._home_dir):
            self.files_visited += len(files)

            # Report progress periodically (time-based)
            if self._on_progress is not None:
                now = time.time()
                if now - self._last_progress_time >= PROGRESS_INTERVAL_SECONDS:
                    self._last_progress_time = now
                    self._on_progress(self.files_visited)

            if self._is_timed_out():
                return

            # Prune directories
            self._prune_directories(dirs)

            for filename in files:
                fpath = Path(root) / filename

                # Skip if already processed in well-known scan
                if fpath in seen_paths:
                    continue

                if self._is_private_key_file(fpath):
                    # Skip files matching exclusion patterns from config
                    if is_path_excluded(fpath, self._exclusion_regexes):
                        continue
                    seen_paths.add(fpath)
                    yield from self._extract_key_from_file(fpath)

    def _prune_directories(self, dirs: list) -> None:
        """Remove directories we should skip from the traversal list."""
        indices_to_remove = []
        for i, dirname in enumerate(dirs):
            if dirname in SKIP_DIRECTORIES:
                indices_to_remove.append(i)
            elif dirname.startswith("."):
                # Skip hidden dirs except allowed ones
                if not any(
                    dirname == allowed or dirname.startswith(allowed)
                    for allowed in ALLOWED_DOT_DIRECTORIES
                ):
                    indices_to_remove.append(i)

        for i in reversed(indices_to_remove):
            del dirs[i]

    def _is_private_key_file(self, fpath: Path) -> bool:
        """Check if file looks like a private key file."""
        name = fpath.name.lower()
        suffix = fpath.suffix.lower()

        # Check by filename
        if name in PRIVATE_KEY_FILENAMES:
            return True

        # Check by extension
        if suffix in PRIVATE_KEY_EXTENSIONS:
            return True

        # Check for common key filename patterns
        if "private" in name and "key" in name:
            return True

        return False

    def _extract_key_from_file(self, fpath: Path) -> Iterator[GatheredSecret]:
        """Extract private key content from a file."""
        try:
            # Check file size first
            stat = fpath.stat()
            if stat.st_size > MAX_KEY_FILE_SIZE:
                return

            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        # Skip empty files
        if not content.strip():
            return

        # Verify it looks like a key file (has BEGIN marker or is small enough)
        if not self._looks_like_key_content(content):
            return

        self.files_found += 1
        self.secrets_found += 1

        # Yield the key content with newlines normalised
        # Format 1: Standard newline-joined format
        yield GatheredSecret(
            value=content.strip(),
            metadata=SecretMetadata(
                source_type=self.source_type,
                source_path=str(fpath),
                secret_name=fpath.name,
            ),
        )

    def _looks_like_key_content(self, content: str) -> bool:
        """Check if content looks like a private key."""
        # Check for common key markers
        key_markers = [
            "-----BEGIN",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "PuTTY-User-Key-File",
        ]
        return any(marker in content for marker in key_markers)
