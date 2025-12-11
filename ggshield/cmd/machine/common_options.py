"""
Common options for machine commands.
"""

from functools import wraps
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar

import click


F = TypeVar("F", bound=Callable[..., Any])

# Default timeout for full-disk scans (5 minutes)
FULL_DISK_DEFAULT_TIMEOUT = 300


def machine_scan_options(f: F) -> F:
    """Common options for all machine scan commands."""

    @click.option(
        "--timeout",
        type=int,
        default=60,
        show_default=True,
        help=(
            "Maximum time in seconds for filesystem scanning. "
            "Use 0 for unlimited. Fast sources (environment variables, "
            "GitHub token) are always scanned regardless of timeout."
        ),
    )
    @click.option(
        "--min-chars",
        type=int,
        default=5,
        show_default=True,
        help="Minimum number of characters for a value to be considered a secret.",
    )
    @click.option(
        "--exclude",
        multiple=True,
        help="Exclude paths matching this glob pattern. Can be specified multiple times.",
        metavar="PATTERNS",
    )
    @click.option(
        "--ignore-config-exclusions",
        is_flag=True,
        default=False,
        help="Don't apply ignored_paths from .gitguardian.yaml config files.",
    )
    @click.option(
        "--deep",
        is_flag=True,
        default=False,
        help=(
            "Send files to GitGuardian API for comprehensive scanning with 500+ "
            "secret detectors. Requires a valid API key."
        ),
    )
    @click.option(
        "--path",
        type=click.Path(exists=True, file_okay=False, resolve_path=True, path_type=Path),
        default=None,
        help=(
            "Scan a specific directory recursively for .env files and private keys. "
            "Skips home-based credential files (AWS, Docker, etc.). "
            "Cannot be used with --full-disk."
        ),
    )
    @click.option(
        "--full-disk",
        is_flag=True,
        default=False,
        help=(
            "Scan the entire filesystem for secrets. "
            f"Auto-increases timeout to {FULL_DISK_DEFAULT_TIMEOUT}s unless --timeout is specified. "
            "Excludes system directories and remote mounts (NFS, CIFS, etc.) by default. "
            "Use --include-remote-mounts to scan network storage. "
            "Use --path to scan specific locations like /mnt/usb. "
            "Cannot be used with --path."
        ),
    )
    @click.option(
        "--include-remote-mounts",
        is_flag=True,
        default=False,
        help=(
            "Include remote/network filesystems (NFS, CIFS, SSHFS, etc.) in full-disk scan. "
            "By default, remote mounts are skipped to avoid scanning large network storage. "
            "Only applies with --full-disk."
        ),
    )
    @wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return f(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


def hmsl_options(f: F) -> F:
    """Options for commands that use HMSL."""

    @click.option(
        "-f",
        "--full-hashes",
        is_flag=True,
        default=False,
        help="Use full hashes when checking against HMSL (uses more credits but more accurate).",
    )
    @click.option(
        "--leaked-threshold",
        type=int,
        default=100,
        show_default=True,
        help=(
            "Hide leaked secrets with >= N occurrences from details "
            "(likely false positives). Use 0 to show all."
        ),
    )
    @wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return f(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


def output_option(f: F) -> F:
    """Option for writing detailed JSON results to file."""

    @click.option(
        "-o",
        "--output",
        type=click.Path(dir_okay=False, writable=True, path_type=Path),
        default=None,
        help="Write detailed JSON results to file.",
    )
    @wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return f(*args, **kwargs)

    return wrapper  # type: ignore[return-value]
