"""
Machine scan command - scans local machine for secrets.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, List, Optional, Tuple

import click


if TYPE_CHECKING:
    from ggshield.verticals.machine.analyzer import AnalysisResult

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
    SOURCE_LABELS,
    display_analyzed_results,
    display_hmsl_check_results,
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
@click.option(
    "--analyze",
    is_flag=True,
    default=False,
    help="Analyze secrets using GitGuardian API for type detection and validity.",
)
@click.option(
    "--check",
    is_flag=True,
    default=False,
    help="Check found secrets against HasMySecretLeaked API for public exposure.",
)
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    default=None,
    help="Write detailed JSON results to file (requires --analyze).",
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
    analyze: bool,
    check: bool,
    output: Optional[Path],
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
    and private key files. Optionally analyzes secrets using the GitGuardian API
    for type detection and validity, or checks if they have been publicly exposed
    using GitGuardian's HasMySecretLeaked service.

    \b
    Sources scanned:
      - Environment variables
      - GitHub CLI token (if `gh` is installed)
      - ~/.npmrc configuration
      - .env* files (recursive scan from home directory)
      - Private key files (SSH, SSL, crypto keys)

    \b
    Examples:
      ggshield machine scan                      # Fast inventory only
      ggshield machine scan --analyze            # Analyze with GitGuardian API
      ggshield machine scan --analyze -v         # Verbose per-secret details
      ggshield machine scan --analyze -o out.json  # Save detailed results
      ggshield machine scan --check              # HMSL leak check
      ggshield machine scan --analyze --check    # Both analysis and leak check
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

    # Validate options
    if output and not analyze:
        raise click.UsageError("--output requires --analyze flag")

    if not secrets:
        if not ctx_obj.use_json:
            ui.display_info("\nNo secrets found.")
        return ExitCode.SUCCESS

    # If neither analyze nor check, just show inventory
    if not analyze and not check:
        display_scan_results(secrets, ctx_obj.use_json, verbose=ui.is_verbose())
        return ExitCode.SUCCESS

    # Handle --analyze (with optional --check)
    if analyze:
        return _run_analysis(
            ctx=ctx,
            secrets=secrets,
            check=check,
            full_hashes=full_hashes,
            output_file=output,
        )

    # Handle --check only (no --analyze)
    return _run_hmsl_check(
        ctx=ctx,
        secrets=secrets,
        full_hashes=full_hashes,
    )


def _run_analysis(
    ctx: click.Context,
    secrets: List[GatheredSecret],
    check: bool,
    full_hashes: bool,
    output_file: Optional[Path],
) -> int:
    """
    Run GitGuardian API analysis on gathered secrets.

    Optionally also run HMSL check if --check flag is set.
    """
    from ggshield.core.client import create_client_from_config
    from ggshield.verticals.machine.analyzer import MachineSecretAnalyzer

    ctx_obj = ContextObj.get(ctx)

    ui.display_info(f"\nAnalyzing {len(secrets)} secrets with GitGuardian API...")

    # Create client and analyzer
    client = create_client_from_config(ctx_obj.config)
    analyzer = MachineSecretAnalyzer(client)

    # Run analysis
    result = analyzer.analyze(secrets)

    # If --check is also set, run HMSL check and merge results
    if check:
        _merge_hmsl_results(ctx, secrets, result, full_hashes)

    # Display results
    display_analyzed_results(
        result,
        json_output=ctx_obj.use_json,
        verbose=ui.is_verbose(),
        output_file=output_file,
    )

    # Return appropriate exit code
    if result.detected_count > 0:
        return ExitCode.SCAN_FOUND_PROBLEMS
    return ExitCode.SUCCESS


# --------------------------------------------------------------------------
# HMSL helper functions
# --------------------------------------------------------------------------


def _prepare_secrets_for_hmsl(secrets: List[GatheredSecret]):
    """Convert gathered secrets to HMSL format."""
    secrets_with_keys = [
        SecretWithKey(
            key=f"{s.metadata.secret_name} ({s.metadata.source_path})",
            value=s.value,
        )
        for s in secrets
    ]
    naming_strategy = NAMING_STRATEGIES["key"]
    return prepare(secrets_with_keys, naming_strategy, full_hashes=True)


def _extract_leaked_keys(found_secrets, prepared_data) -> set:
    """Extract leaked secret keys from HMSL response."""
    leaked_keys: set = set()
    for secret in found_secrets:
        name = prepared_data.mapping.get(secret.hash)
        if name:
            leaked_keys.add(name)
    return leaked_keys


def _merge_hmsl_results(
    ctx: click.Context,
    secrets: List[GatheredSecret],
    result: AnalysisResult,
    full_hashes: bool,
) -> None:
    """
    Run HMSL check and merge leaked status into analysis results.
    """
    from ggshield.verticals.hmsl.client import HMSLClient
    from ggshield.verticals.hmsl.utils import get_client

    ui.display_info("Checking secrets against HasMySecretLeaked...")

    prepared_data = _prepare_secrets_for_hmsl(secrets)

    # Get HMSL client and check
    ctx_obj = ContextObj.get(ctx)
    hmsl_client: HMSLClient = get_client(ctx_obj.config, ctx.command_path)

    # Query HMSL
    found_secrets = hmsl_client.check(prepared_data.payload, full_hashes=full_hashes)
    leaked_keys = _extract_leaked_keys(found_secrets, prepared_data)

    # Merge into analysis results
    for analyzed in result.analyzed_secrets:
        metadata = analyzed.gathered_secret.metadata
        key = f"{metadata.secret_name} ({metadata.source_path})"
        analyzed.hmsl_leaked = key in leaked_keys

    leaked_count = sum(1 for a in result.analyzed_secrets if a.hmsl_leaked)
    if leaked_count > 0:
        ui.display_warning(f"Found {leaked_count} leaked secrets!")


def _run_hmsl_check(
    ctx: click.Context,
    secrets: List[GatheredSecret],
    full_hashes: bool,
) -> int:
    """Run HMSL check only (no API analysis)."""
    from ggshield.verticals.hmsl.client import HMSLClient
    from ggshield.verticals.hmsl.utils import get_client

    ui.display_info(f"\nChecking {len(secrets)} secrets against HasMySecretLeaked...")

    prepared_data = _prepare_secrets_for_hmsl(secrets)

    # Get HMSL client and check
    ctx_obj = ContextObj.get(ctx)
    hmsl_client: HMSLClient = get_client(ctx_obj.config, ctx.command_path)

    # Query HMSL
    found_secrets = hmsl_client.check(prepared_data.payload, full_hashes=full_hashes)
    leaked_keys = _extract_leaked_keys(found_secrets, prepared_data)

    # Display results
    display_hmsl_check_results(
        secrets,
        leaked_keys,
        json_output=ctx_obj.use_json,
        verbose=ui.is_verbose(),
    )

    # Return appropriate exit code
    if leaked_keys:
        return ExitCode.SCAN_FOUND_PROBLEMS
    return ExitCode.SUCCESS
