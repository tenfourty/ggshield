"""
Machine scan command - gathers secrets from the local machine.

This command is the fastest option for getting an inventory of potential secrets.
No network calls are made.
"""

from __future__ import annotations

import logging
import sys
from typing import Any, List, Optional, Tuple

import click

from ggshield.cmd.machine.common_options import machine_scan_options
from ggshield.cmd.utils.common_options import (
    add_common_options,
    json_option,
    text_json_format_option,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
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

    def on_progress(self, phase: str, files_visited: int, elapsed: float) -> None:
        """Update the spinner during filesystem scans."""
        if not self.enabled:
            return

        self._total_files_visited = files_visited
        self._elapsed_seconds = elapsed

        spinner = SPINNER_CHARS[self.spinner_index % len(SPINNER_CHARS)]
        self.spinner_index += 1

        # Handle unified phase format "Scanning home directory | .env: N | keys: N"
        if " | " in phase:
            parts = phase.split(" | ")
            base_phase = parts[0]
            counts = " | ".join(parts[1:])
            msg = (
                f"\r  {spinner} {base_phase}... "
                f"{files_visited:,} files ({elapsed:.1f}s) | {counts}"
            )
        else:
            msg = f"\r  {spinner} {phase}... {files_visited:,} files ({elapsed:.1f}s)"

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
    **kwargs: Any,
) -> int:
    """
    Scan the local machine for secrets (fast inventory, no network calls).

    Gathers potential secrets from environment variables, configuration files,
    and private key files. This is the fastest option for getting an inventory
    of potential secrets on your machine.

    \b
    For more detailed analysis, use:
      - `ggshield machine check` - Check for public leaks (sends hashes only)
      - `ggshield machine analyze` - Full analysis with GitGuardian API

    \b
    Sources scanned:
      - Environment variables
      - GitHub CLI token (if `gh` is installed)
      - ~/.npmrc configuration
      - .env* files (recursive scan from home directory)
      - Private key files (SSH, SSL, crypto keys)

    \b
    Examples:
      ggshield machine scan              # Fast inventory
      ggshield machine scan --json       # JSON output
      ggshield machine scan --timeout 30 # Limit scan time
      ggshield machine scan -v           # Verbose output
    """
    ctx_obj = ContextObj.get(ctx)

    # Don't show progress for JSON output
    show_progress = not ctx_obj.use_json

    # Build exclusion patterns from config and CLI options
    exclusion_patterns: set[str] = set()

    # Add patterns from config unless ignored
    if not ignore_config_exclusions:
        exclusion_patterns.update(ctx_obj.config.user_config.secret.ignored_paths)

    # Add patterns from CLI --exclude options
    exclusion_patterns.update(exclude)

    # Convert to regex patterns
    exclusion_regexes = init_exclusion_regexes(exclusion_patterns)

    if show_progress:
        ui.display_info("Scanning machine for secrets...\n")

    with ScanProgressReporter(enabled=show_progress) as progress:
        config = GatheringConfig(
            timeout=timeout,
            min_chars=min_chars,
            verbose=ui.is_verbose(),
            on_progress=progress.on_progress,
            on_source_complete=progress.on_source_complete,
            exclusion_regexes=exclusion_regexes,
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
