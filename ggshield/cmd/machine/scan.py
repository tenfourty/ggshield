"""
Machine scan command - scans local machine for secrets.
"""

import logging
import sys
from typing import Any, List, Optional, Tuple

import click

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
from ggshield.verticals.hmsl.collection import (
    NAMING_STRATEGIES,
    SecretWithKey,
    prepare,
)
from ggshield.verticals.machine.output import (
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

# Human-readable labels for source types
SOURCE_LABELS = {
    SourceType.ENVIRONMENT_VAR: "Environment variables",
    SourceType.GITHUB_TOKEN: "GitHub token",
    SourceType.NPMRC: "NPM configuration",
    SourceType.ENV_FILE: "Environment files",
    SourceType.PRIVATE_KEY: "Private keys",
}


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

        if result.source_type == SourceType.ENVIRONMENT_VAR:
            status = str(result.secrets_found)
        elif result.source_type == SourceType.GITHUB_TOKEN:
            status = result.message or ("found" if result.secrets_found else "not found")
        elif result.source_type == SourceType.NPMRC:
            status = result.message or "not found"
        elif result.source_type == SourceType.ENV_FILE:
            status = (
                f"{result.files_scanned} {pluralize('file', result.files_scanned)}, "
                f"{result.secrets_found} {pluralize('secret', result.secrets_found)}"
            )
        elif result.source_type == SourceType.PRIVATE_KEY:
            status = f"{result.files_scanned} {pluralize('file', result.files_scanned)}"
        else:
            status = str(result.secrets_found)

        # Use checkmark for completed, x for not found
        if result.status == SourceStatus.NOT_FOUND:
            icon = "○"
        else:
            icon = "✓"

        self._write_line(f"  {icon} {label}: {status}")

    def on_progress(self, phase: str, files_visited: int, elapsed: float) -> None:
        """Update the spinner during filesystem scans."""
        if not self.enabled:
            return

        self._total_files_visited = files_visited
        self._elapsed_seconds = elapsed

        spinner = SPINNER_CHARS[self.spinner_index % len(SPINNER_CHARS)]
        self.spinner_index += 1

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
@click.option(
    "--check",
    is_flag=True,
    default=False,
    help="Check found secrets against HasMySecretLeaked API for public exposure.",
)
@click.option(
    "-f",
    "--full-hashes",
    is_flag=True,
    default=False,
    help="Use full hashes when checking against HMSL (uses more credits but more accurate).",
)
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
    metavar="PATTERN",
)
@click.option(
    "--ignore-config-exclusions",
    is_flag=True,
    default=False,
    help="Don't apply ignored_paths from .gitguardian.yaml config files.",
)
def scan_cmd(
    ctx: click.Context,
    check: bool,
    full_hashes: bool,
    timeout: int,
    min_chars: int,
    exclude: Tuple[str, ...],
    ignore_config_exclusions: bool,
    **kwargs: Any,
) -> int:
    """
    Scan the local machine for secrets.

    Gathers potential secrets from environment variables, configuration files,
    and private key files. Optionally checks if found secrets have been
    publicly exposed using GitGuardian's HasMySecretLeaked service.

    \b
    Sources scanned:
      - Environment variables
      - GitHub CLI token (if `gh` is installed)
      - ~/.npmrc configuration
      - .env* files (recursive scan from home directory)
      - Private key files (SSH, SSL, crypto keys)

    \b
    Examples:
      ggshield machine scan                    # Fast inventory only
      ggshield machine scan --check            # Inventory + HMSL leak check
      ggshield machine scan --check --timeout 30  # With 30s filesystem timeout
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

    if not check:
        display_scan_results(secrets, ctx_obj.use_json)
        return ExitCode.SUCCESS

    # Check against HMSL
    ui.display_info(f"Checking {len(secrets)} secrets against HasMySecretLeaked...")

    # Convert to format expected by HMSL
    # Include source path so users know where to fix leaked secrets
    secrets_with_keys = [
        SecretWithKey(
            key=f"{s.metadata.secret_name} ({s.metadata.source_path})",
            value=s.value,
        )
        for s in secrets
    ]

    naming_strategy = NAMING_STRATEGIES["key"]
    prepared_data = prepare(secrets_with_keys, naming_strategy, full_hashes=True)

    ui.display_info(f"Prepared {len(prepared_data.payload)} unique secret hashes.")

    # Import here to avoid circular imports
    from ggshield.cmd.hmsl.hmsl_utils import check_secrets

    check_secrets(
        ctx=ctx,
        prepared_secrets=prepared_data,
        full_hashes=full_hashes,
    )

    return ExitCode.SUCCESS
