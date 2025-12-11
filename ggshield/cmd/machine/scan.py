"""
Machine scan command - gathers secrets from the local machine.

This command is the fastest option for getting an inventory of potential secrets.
No network calls are made by default. Use --deep for comprehensive API-based scanning.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, List, Optional, Tuple

import click
from pygitguardian.models import TokenScope

from ggshield.cmd.machine.common_options import (
    FULL_DISK_DEFAULT_TIMEOUT,
    machine_scan_options,
)
from ggshield.cmd.utils.common_options import (
    add_common_options,
    json_option,
    text_json_format_option,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.client import check_client_api_key, create_client_from_config
from ggshield.core.errors import ExitCode
from ggshield.core.filter import init_exclusion_regexes
from ggshield.core.text_utils import pluralize
from ggshield.verticals.machine.output import (
    SOURCE_LABELS,
    display_scan_results,
)
from ggshield.verticals.machine.secret_gatherer import (
    GatheringConfig,
    MachineSecretGatherer,
    ScanMode,
    SourceResult,
    SourceStatus,
)
from ggshield.verticals.machine.sources import GatheredSecret, SourceType


logger = logging.getLogger(__name__)


# Progress spinner characters (braille pattern)
SPINNER_CHARS = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


def _format_source_status(result: SourceResult) -> str:
    """Format status string based on source type."""
    if result.source_type == SourceType.ENVIRONMENT_VAR:
        return str(result.secrets_found)
    elif result.source_type == SourceType.GITHUB_TOKEN:
        return result.message or ("found" if result.secrets_found else "not found")
    elif result.source_type == SourceType.NPMRC:
        return result.message or "not found"
    elif result.source_type == SourceType.ENV_FILE:
        return (
            f"{result.files_scanned} {pluralize('file', result.files_scanned)}, "
            f"{result.secrets_found} {pluralize('secret', result.secrets_found)}"
        )
    elif result.source_type == SourceType.PRIVATE_KEY:
        return f"{result.files_scanned} {pluralize('file', result.files_scanned)}"
    return str(result.secrets_found)


class ScanProgressReporter:
    """Reports scan progress with live source status updates."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled and sys.stderr.isatty()
        self.spinner_index = 0
        self._current_spinner_line: Optional[str] = None
        self._total_files_visited = 0
        self._elapsed_seconds = 0.0

    def __enter__(self) -> "ScanProgressReporter":
        return self

    def __exit__(self, *args: Any) -> None:
        self._clear_spinner()

    def _clear_spinner(self) -> None:
        """Clear the current spinner line if any."""
        if self.enabled and self._current_spinner_line:
            sys.stderr.write("\r" + " " * 80 + "\r")
            sys.stderr.flush()
            self._current_spinner_line = None

    def _write_line(self, line: str) -> None:
        """Write a permanent line (clears spinner first)."""
        if not self.enabled:
            return
        self._clear_spinner()
        sys.stderr.write(line + "\n")
        sys.stderr.flush()

    def on_source_complete(self, result: SourceResult) -> None:
        """Handle source completion - print status line."""
        if not self.enabled:
            return

        label = SOURCE_LABELS.get(result.source_type, result.source_type.name)
        status = _format_source_status(result)

        # Use checkmark for completed, x for not found
        icon = "○" if result.status == SourceStatus.NOT_FOUND else "✓"

        self._write_line(f"  {icon} {label}: {status}")

        # For DEEP_SCAN, show detector breakdown
        if result.source_type == SourceType.DEEP_SCAN and result.detector_counts:
            # Sort by count descending
            sorted_detectors = sorted(
                result.detector_counts.items(), key=lambda x: -x[1]
            )
            for detector, count in sorted_detectors:
                self._write_line(f"      {detector}: {count}")

    def on_progress(
        self, phase: str, files_visited: int, elapsed: float, current_dir: str = ""
    ) -> None:
        """Update the spinner during filesystem scans."""
        if not self.enabled:
            return

        self._total_files_visited = files_visited
        self._elapsed_seconds = elapsed

        spinner = SPINNER_CHARS[self.spinner_index % len(SPINNER_CHARS)]
        self.spinner_index += 1

        # Truncate long paths for display
        dir_display = ""
        if current_dir:
            max_dir_len = 40
            if len(current_dir) > max_dir_len:
                current_dir = "..." + current_dir[-(max_dir_len - 3) :]
            dir_display = f" [{current_dir}]"

        # Handle unified phase format "Scanning home directory | .env: N | keys: N"
        if " | " in phase:
            parts = phase.split(" | ")
            base_phase = parts[0]
            counts = " | ".join(parts[1:])
            msg = (
                f"\r  {spinner} {base_phase}... "
                f"{files_visited:,} files ({elapsed:.1f}s) | {counts}{dir_display}"
            )
        else:
            msg = f"\r  {spinner} {phase}... {files_visited:,} files ({elapsed:.1f}s){dir_display}"

        self._current_spinner_line = msg
        sys.stderr.write(msg)
        sys.stderr.flush()

    def show_summary(self, stats: Any) -> None:
        """Show final summary line."""
        if not self.enabled:
            return

        self._clear_spinner()

        # Show total files visited and time
        if stats.total_files_visited > 0:
            self._write_line(
                f"  Total: {stats.total_files_visited:,} files visited "
                f"({stats.elapsed_seconds:.1f}s)"
            )


@click.command()
@click.pass_context
@add_common_options()
@text_json_format_option
@json_option
@machine_scan_options
def scan_cmd(
    ctx: click.Context,
    timeout: int,
    min_chars: int,
    exclude: Tuple[str, ...],
    ignore_config_exclusions: bool,
    deep: bool,
    path: Optional[Path],
    full_disk: bool,
    include_remote_mounts: bool,
    **kwargs: Any,
) -> int:
    """
    Scan the local machine for secrets (fast inventory).

    [Alpha] This command is under active development and may change.

    Gathers potential secrets from environment variables, configuration files,
    and private key files. This is the fastest option for getting an inventory
    of potential secrets on your machine.

    \b
    For more detailed analysis, use:
      - `ggshield machine check` - Check for public leaks (sends hashes only)
      - `ggshield machine analyze` - Full analysis with GitGuardian API

    \b
    Sources scanned (default mode):
      - Environment variables
      - GitHub CLI token (if `gh` is installed)
      - ~/.npmrc configuration
      - Credential files (AWS, Docker, GCP, etc.)
      - .env* files (recursive scan from home directory)
      - Private key files (SSH, SSL, crypto keys)

    \b
    With --path:
      - Scans only the specified directory
      - Finds .env files and private keys
      - Skips home-based credential files

    \b
    With --full-disk:
      - Scans the entire filesystem
      - Includes all credential sources
      - Excludes system directories and remote mounts (NFS, CIFS, etc.)
      - Use --include-remote-mounts to scan network storage
      - Use --path to scan specific locations like /mnt/usb
      - Auto-increases timeout to 300s

    \b
    With --deep flag:
      - Sends config files (.json, .yaml, etc.) to GitGuardian API
      - Uses 500+ secret detectors for comprehensive scanning
      - Requires a valid API key

    \b
    Examples:
      ggshield machine scan                     # Fast local inventory
      ggshield machine scan --path /opt/myapp   # Scan specific directory
      ggshield machine scan --full-disk         # Scan entire filesystem
      ggshield machine scan --deep              # Include API-based deep scan
      ggshield machine scan --json              # JSON output
      ggshield machine scan --timeout 30        # Limit scan time
      ggshield machine scan -v                  # Verbose output
    """
    ctx_obj = ContextObj.get(ctx)

    # Validate mutually exclusive options
    if path is not None and full_disk:
        raise click.UsageError("--path and --full-disk are mutually exclusive.")

    # Determine scan mode and effective timeout
    if full_disk:
        scan_mode = ScanMode.FULL_DISK
        # Auto-increase timeout if user didn't specify one (60 is the default)
        effective_timeout = timeout if timeout != 60 else FULL_DISK_DEFAULT_TIMEOUT
    elif path is not None:
        scan_mode = ScanMode.PATH
        effective_timeout = timeout
    else:
        scan_mode = ScanMode.HOME
        effective_timeout = timeout

    # Show alpha warning (not in JSON mode)
    if not ctx_obj.use_json:
        ui.display_warning(
            "Alpha feature: This command is under active development and may change."
        )

    # Don't show progress for JSON output
    show_progress = not ctx_obj.use_json

    # Create client if deep scan is enabled
    client = None
    if deep:
        client = create_client_from_config(ctx_obj.config)
        check_client_api_key(client, {TokenScope.SCAN})

    # Build exclusion patterns from config and CLI options
    exclusion_patterns: set[str] = set()

    # Add patterns from config unless ignored or using --path
    # (when using --path, user is being explicit about what to scan)
    if not ignore_config_exclusions and path is None:
        exclusion_patterns.update(ctx_obj.config.user_config.secret.ignored_paths)

    # Add patterns from CLI --exclude options
    exclusion_patterns.update(exclude)

    # Convert to regex patterns
    exclusion_regexes = init_exclusion_regexes(exclusion_patterns)

    # Show appropriate progress message
    if show_progress:
        if full_disk:
            ui.display_warning(
                "Full disk scan enabled. This may take a long time and scan sensitive areas. "
                f"Timeout set to {effective_timeout}s."
            )
            ui.display_info("Scanning entire filesystem for secrets...\n")
        elif path:
            ui.display_info(f"Scanning {path} for secrets...\n")
        elif deep:
            ui.display_info("Scanning machine for secrets (deep mode)...\n")
        else:
            ui.display_info("Scanning machine for secrets...\n")

    with ScanProgressReporter(enabled=show_progress) as progress:
        config = GatheringConfig(
            timeout=effective_timeout,
            min_chars=min_chars,
            verbose=ui.is_verbose(),
            scan_mode=scan_mode,
            scan_path=path,
            on_progress=progress.on_progress,
            on_source_complete=progress.on_source_complete,
            exclusion_regexes=exclusion_regexes,
            deep_scan=deep,
            client=client,
            include_remote_mounts=include_remote_mounts,
        )

        gatherer = MachineSecretGatherer(config)
        secrets: List[GatheredSecret] = list(gatherer.gather())

        # Show summary after all sources complete
        progress.show_summary(gatherer.stats)

    # Show timeout warning via ui module (appears in stdout for tests/non-TTY)
    if gatherer.stats.timed_out:
        ui.display_warning(
            "Scan timed out. Some files may not have been scanned. "
            "Use --timeout to increase the limit."
        )

    if not secrets:
        if not ctx_obj.use_json:
            ui.display_info("\nNo secrets found.")
        return ExitCode.SUCCESS

    # Display inventory results
    display_scan_results(secrets, ctx_obj.use_json, verbose=ui.is_verbose())
    return ExitCode.SUCCESS
