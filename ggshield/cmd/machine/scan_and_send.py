"""
Machine scan-and-send command - scan, analyze, and upload to GitGuardian.

This command gathers secrets, optionally analyzes them, and uploads
the inventory to GitGuardian for centralized tracking.
"""

from __future__ import annotations

import logging
import socket
from pathlib import Path
from typing import TYPE_CHECKING, Any, List, Tuple

import click

from ggshield import __version__
from ggshield.cmd.machine.analyze import _merge_hmsl_results, check_leaks
from ggshield.cmd.machine.common_options import (
    hmsl_options,
    machine_scan_options,
    output_option,
)
from ggshield.cmd.machine.scan import ScanProgressReporter
from ggshield.cmd.utils.common_options import (
    add_common_options,
    json_option,
    text_json_format_option,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.errors import ExitCode
from ggshield.core.filter import init_exclusion_regexes
from ggshield.verticals.machine.inventory import (
    InventoryClient,
    NHIAuthError,
    build_inventory_from_analysis,
    build_inventory_from_scan,
)
from ggshield.verticals.machine.output import display_analyzed_results
from ggshield.verticals.machine.secret_gatherer import (
    GatheringConfig,
    MachineSecretGatherer,
)
from ggshield.verticals.machine.sources import GatheredSecret


if TYPE_CHECKING:
    from ggshield.verticals.machine.analyzer import AnalysisResult


logger = logging.getLogger(__name__)


@click.command()
@click.pass_context
@add_common_options()
@text_json_format_option
@json_option
@output_option
@hmsl_options
@machine_scan_options
@click.option(
    "--env",
    type=click.Choice(
        ["production", "staging", "development", "testing", "pre-production"]
    ),
    default="development",
    help="Environment classification for the inventory.",
)
@click.option(
    "--source-name",
    type=str,
    default=None,
    help="Override machine hostname as source name.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show payload without uploading to GitGuardian.",
)
@click.option(
    "--skip-analysis",
    is_flag=True,
    help="Skip API analysis (only send hashes, no secrets sent to API).",
)
def scan_and_send_cmd(
    ctx: click.Context,
    output: Path | None,
    full_hashes: bool,
    timeout: int,
    min_chars: int,
    exclude: Tuple[str, ...],
    ignore_config_exclusions: bool,
    env: str,
    source_name: str | None,
    dry_run: bool,
    skip_analysis: bool,
    **kwargs: Any,
) -> int:
    """
    Scan machine for secrets and send inventory to GitGuardian.

    This command runs the full analysis pipeline and uploads the discovered
    secrets to GitGuardian for centralized tracking and management.

    \b
    IMPORTANT: Only hashes are uploaded to GitGuardian, not actual secret values.

    \b
    AUTHENTICATION:
      Requires a service account with 'nhi:send-inventory' scope.
      Set via: GITGUARDIAN_NHI_API_KEY environment variable
      Or use GITGUARDIAN_API_KEY if it has NHI permissions.

    \b
    Pipeline steps:
      1. Gather secrets from local sources
      2. Check for public leaks via HMSL (hashes only)
      3. Analyze with GitGuardian API (for local output)
      4. Upload inventory to GitGuardian (hashes only)

    \b
    With --skip-analysis:
      - Skips steps 2-3 (HMSL check and API analysis)
      - Only gathers secrets and uploads hashes
      - No secrets are sent to any API

    \b
    Examples:
      export GITGUARDIAN_NHI_API_KEY="your-service-account-key"
      ggshield machine scan-and-send                    # Upload with defaults
      ggshield machine scan-and-send --env production   # Set environment
      ggshield machine scan-and-send --dry-run          # Preview without uploading
      ggshield machine scan-and-send --skip-analysis    # No secrets sent to API
      ggshield machine scan-and-send -o results.json    # Save detailed results locally
    """
    from ggshield.core.client import create_client_from_config
    from ggshield.verticals.machine.analyzer import MachineSecretAnalyzer

    ctx_obj = ContextObj.get(ctx)

    # Use hostname if source-name not provided
    hostname = source_name or socket.gethostname()

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

    # Gather secrets with progress reporting
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

    # Show timeout warning
    if gatherer.stats.timed_out:
        ui.display_warning(
            "Scan timed out. Some files may not have been scanned. "
            "Use --timeout to increase the limit."
        )

    if not secrets:
        if not ctx_obj.use_json:
            ui.display_info("\nNo secrets found.")
        return ExitCode.SUCCESS

    result: AnalysisResult | None = None

    if skip_analysis:
        # Skip analysis - build inventory from raw scan
        if show_progress:
            ui.display_info(
                f"\nBuilding inventory from {len(secrets)} secrets (skipping analysis)..."
            )
        payload = build_inventory_from_scan(secrets, hostname, env)
    else:
        # Full pipeline - gather → HMSL check → API analyze
        if show_progress:
            ui.display_info(
                f"\nAnalyzing {len(secrets)} secrets with GitGuardian API..."
            )

        # Create client and analyzer
        client = create_client_from_config(ctx_obj.config)
        analyzer = MachineSecretAnalyzer(client)

        # Run analysis
        result = analyzer.analyze(secrets)

        # Run HMSL check and merge results
        if show_progress:
            ui.display_info("Checking secrets against HasMySecretLeaked...")

        leaked_keys = check_leaks(ctx, secrets, full_hashes=full_hashes)
        _merge_hmsl_results(secrets, result, leaked_keys)

        leaked_count = sum(1 for a in result.analyzed_secrets if a.hmsl_leaked)
        if leaked_count > 0:
            ui.display_warning(f"Found {leaked_count} leaked secrets!")

        # Build inventory with enrichment
        payload = build_inventory_from_analysis(result, hostname, env)

    # Dry run - show payload without uploading
    if dry_run:
        import json

        if show_progress:
            ui.display_info("\nDry run - payload that would be uploaded:\n")
        # Pretty-print for readability
        click.echo(json.dumps(json.loads(payload.to_json()), indent=2))
        return ExitCode.SUCCESS

    # Upload to GitGuardian inventory
    if show_progress:
        ui.display_info("\nUploading inventory to GitGuardian...")

    inventory_client = InventoryClient(
        api_url=ctx_obj.config.api_url,
        api_key=ctx_obj.config.nhi_api_key,
        agent_version=f"ggshield/{__version__}",
    )

    try:
        response = inventory_client.upload(payload)
        raw_data_id = response.get("raw_data_id", "unknown")
        ui.display_info(f"Inventory uploaded successfully (ID: {raw_data_id})")
    except NHIAuthError as e:
        ui.display_error(f"\n✗ {e}")
        return ExitCode.UNEXPECTED_ERROR
    except Exception as e:
        logger.exception("Failed to upload inventory")
        ui.display_error(f"Failed to upload inventory: {e}")
        return ExitCode.UNEXPECTED_ERROR

    # Display local results if we ran analysis
    if result:
        display_analyzed_results(
            result,
            json_output=ctx_obj.use_json,
            verbose=ui.is_verbose(),
            output_file=output,
        )

    # Return appropriate exit code
    if result and result.detected_count > 0:
        return ExitCode.SCAN_FOUND_PROBLEMS
    return ExitCode.SUCCESS
