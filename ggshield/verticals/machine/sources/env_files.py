"""
Environment file (.env*) secret source.
"""

import os
import re
from pathlib import Path
from typing import Callable, Iterator, Optional, Pattern, Set

from ggshield.utils.files import is_path_excluded
from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)
from ggshield.verticals.machine.sources.base import SecretSource


# Regex to extract KEY=value assignments
ASSIGNMENT_REGEX = re.compile(
    r"""
    ^\s*
    (?P<name>[a-zA-Z_]\w*)
    \s*=\s*
    (?P<value>.{1,5000})
""",
    re.VERBOSE,
)

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
ALLOWED_DOT_DIRECTORIES = {".env", ".ssh", ".gnupg", ".aws", ".config"}


# Type for progress callback: (files_visited) -> None
ProgressCallback = Callable[[int], None]

# Progress update interval in seconds
PROGRESS_INTERVAL_SECONDS = 0.2


class EnvFileSource(SecretSource):
    """
    Collects secrets from .env* files in the home directory.

    Recursively scans the home directory for files starting with '.env'
    (but not example files) and extracts KEY=value pairs.
    """

    def __init__(
        self,
        home_dir: Optional[Path] = None,
        timeout: int = 0,
        min_chars: int = 5,
        is_timed_out: Optional[Callable[[], bool]] = None,
        on_progress: Optional[ProgressCallback] = None,
        exclusion_regexes: Optional[Set[Pattern[str]]] = None,
    ):
        """
        Initialize env file source.

        Args:
            home_dir: Home directory to scan. Defaults to user's home.
            timeout: Timeout in seconds (0 = no timeout). Used for stats only;
                     actual timeout checking is done via is_timed_out callback.
            min_chars: Minimum character length for values.
            is_timed_out: Callback to check if scan has timed out.
            on_progress: Callback to report progress (receives files_visited).
            exclusion_regexes: Patterns for paths to exclude (from config).
        """
        self._home_dir = home_dir or Path.home()
        self._timeout = timeout
        self._min_chars = min_chars
        self._is_timed_out = is_timed_out or (lambda: False)
        self._on_progress = on_progress
        self._exclusion_regexes = exclusion_regexes or set()
        self._last_progress_time = 0.0
        self.files_found = 0
        self.secrets_found = 0
        self.files_visited = 0

    @property
    def source_type(self) -> SourceType:
        return SourceType.ENV_FILE

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from .env* files.

        Walks the home directory tree, skipping common non-relevant
        directories, and extracts KEY=value pairs from .env files.
        """
        for fpath in self._walk_for_env_files():
            if self._is_timed_out():
                return

            yield from self._extract_secrets_from_file(fpath)

    def _walk_for_env_files(self) -> Iterator[Path]:
        """Walk directory tree and yield .env* file paths."""
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

            # Prune directories we don't want to traverse
            self._prune_directories(dirs)

            # Find .env* files
            for filename in files:
                if self._is_env_file(filename):
                    fpath = Path(root) / filename
                    # Skip files matching exclusion patterns from config
                    if is_path_excluded(fpath, self._exclusion_regexes):
                        continue
                    self.files_found += 1
                    yield fpath

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

        # Remove in reverse order to preserve indices
        for i in reversed(indices_to_remove):
            del dirs[i]

    def _is_env_file(self, filename: str) -> bool:
        """Check if filename is a .env file (but not an example)."""
        if not filename.startswith(".env"):
            return False
        # Skip example files
        lower = filename.lower()
        if "example" in lower or "sample" in lower or "template" in lower:
            return False
        return True

    def _extract_secrets_from_file(self, fpath: Path) -> Iterator[GatheredSecret]:
        """Extract KEY=value pairs from a file."""
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        for line in content.splitlines():
            match = ASSIGNMENT_REGEX.match(line)
            if not match:
                continue

            name = match.group("name")
            value = match.group("value").strip()

            # Handle inline comments
            if "#" in value:
                value = value.split("#")[0].strip()

            # Remove quotes
            value = self._remove_quotes(value)

            # Skip empty or too short values
            if len(value) < self._min_chars:
                continue

            self.secrets_found += 1
            yield GatheredSecret(
                value=value,
                metadata=SecretMetadata(
                    source_type=self.source_type,
                    source_path=str(fpath),
                    secret_name=name,
                ),
            )

    def _remove_quotes(self, value: str) -> str:
        """Remove surrounding quotes from a value."""
        if len(value) > 1 and value[0] == value[-1] and value[0] in ["'", '"']:
            return value[1:-1]
        return value
