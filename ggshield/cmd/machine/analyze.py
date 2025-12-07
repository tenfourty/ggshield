"""
Machine analyze command - full analysis pipeline.

This command gathers secrets, checks them against HMSL for leaks,
and analyzes them using the GitGuardian API for detector type and validity.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Tuple

import click

from ggshield.cmd.machine.common_options import (
    hmsl_options,
    machine_scan_options,
    output_option,
)

# Import progress reporter from scan module
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
from ggshield.verticals.hmsl.collection import (
    NAMING_STRATEGIES,
    PreparedSecrets,
    SecretWithKey,
    prepare,
)
from ggshield.verticals.machine.output import LeakedSecretInfo, display_analyzed_results
from ggshield.verticals.machine.secret_gatherer import (
    GatheringConfig,
    MachineSecretGatherer,
)
from ggshield.verticals.machine.sources import GatheredSecret


if TYPE_CHECKING:
    from ggshield.verticals.machine.analyzer import AnalysisResult


logger = logging.getLogger(__name__)


def _prepare_secrets_for_hmsl(secrets: List[GatheredSecret]) -> PreparedSecrets:
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


def check_leaks(
    ctx: click.Context,
    secrets: List[GatheredSecret],
    full_hashes: bool = False,
) -> Dict[str, LeakedSecretInfo]:
    """
    Check secrets against HMSL and return leaked secret info.

    This function is designed to be patchable in tests.

    Returns:
        Dict mapping key (name + path) to LeakedSecretInfo.
    """
    from ggshield.verticals.hmsl.client import HMSLClient
    from ggshield.verticals.hmsl.utils import get_client

    prepared_data = _prepare_secrets_for_hmsl(secrets)

    # Build reverse mapping from key to secret value
    key_to_value: Dict[str, str] = {}
    for s in secrets:
        key = f"{s.metadata.secret_name} ({s.metadata.source_path})"
        key_to_value[key] = s.value

    # Get HMSL client and check
    ctx_obj = ContextObj.get(ctx)
    hmsl_client: HMSLClient = get_client(ctx_obj.config, ctx.command_path)

    # Query HMSL
    found_secrets = hmsl_client.check(prepared_data.payload, full_hashes=full_hashes)

    # Extract leaked info with full details
    leaked_info: Dict[str, LeakedSecretInfo] = {}
    for secret in found_secrets:
        name = prepared_data.mapping.get(secret.hash)
        if name:
            leaked_info[name] = LeakedSecretInfo(
                key=name,
                count=secret.count,
                url=secret.url,
                secret_value=key_to_value.get(name, ""),
            )

    return leaked_info


def _merge_hmsl_results(
    secrets: List[GatheredSecret],
    result: AnalysisResult,
    leaked_info: Dict[str, LeakedSecretInfo],
) -> None:
    """
    Merge HMSL leaked status and details into analysis results.
    """
    for analyzed in result.analyzed_secrets:
        metadata = analyzed.gathered_secret.metadata
        key = f"{metadata.secret_name} ({metadata.source_path})"
        info = leaked_info.get(key)
        if info:
            analyzed.hmsl_leaked = True
            analyzed.hmsl_occurrences = info.count
            analyzed.hmsl_url = info.url
        else:
            analyzed.hmsl_leaked = False


@click.command()
@click.pass_context
@add_common_options()
@text_json_format_option
@json_option
@output_option
@hmsl_options
@machine_scan_options
def analyze_cmd(
    ctx: click.Context,
    output: Path | None,
    full_hashes: bool,
    leaked_threshold: int,
    timeout: int,
    min_chars: int,
    exclude: Tuple[str, ...],
    ignore_config_exclusions: bool,
    deep: bool,
    **kwargs: Any,
) -> int:
    """
    Scan, check for public leaks, and analyze with GitGuardian API.

    [Alpha] This command is under active development and may change.

    This command provides comprehensive analysis of secrets found on your machine:

    \b
    1. Gathers potential secrets from local sources
    2. Checks for public leaks using HasMySecretLeaked (hashes only)
    3. Analyzes secrets with GitGuardian API for:
       - Secret type detection (e.g., AWS Key, GitHub Token)
       - Validity status (valid/invalid/unknown)
       - Known incident matching

    Note: This command sends secrets to the GitGuardian API for analysis.
    Use `ggshield machine check` if you only want to check for public leaks without
    sending secret values.

    \b
    Sources scanned:
      - Environment variables
      - GitHub CLI token (if `gh` is installed)
      - ~/.npmrc configuration
      - .env* files (recursive scan from home directory)
      - Private key files (SSH, SSL, crypto keys)

    \b
    With --deep flag:
      - Also sends config files (.json, .yaml, etc.) to GitGuardian API
      - Uses 500+ secret detectors for comprehensive scanning

    \b
    Examples:
      ggshield machine analyze                # Full analysis
      ggshield machine analyze --deep         # Include API-based deep scan
      ggshield machine analyze -v             # Verbose per-secret details
      ggshield machine analyze -o out.json    # Save detailed results to file
      ggshield machine analyze --json         # JSON output to stdout
      ggshield machine analyze --full-hashes  # More accurate HMSL check
    """
    from ggshield.core.client import create_client_from_config
    from ggshield.verticals.machine.analyzer import MachineSecretAnalyzer

    ctx_obj = ContextObj.get(ctx)

    # Show alpha warning (not in JSON mode)
    if not ctx_obj.use_json:
        ui.display_warning(
            "Alpha feature: This command is under active development and may change."
        )

    # Don't show progress for JSON output
    show_progress = not ctx_obj.use_json

    # Create client (always needed for analyze, also used for deep scan)
    client = create_client_from_config(ctx_obj.config)

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
        if deep:
            ui.display_info("Scanning machine for secrets (deep mode)...\n")
        else:
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
            deep_scan=deep,
            client=client if deep else None,  # Only pass client if deep scan
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

    if show_progress:
        ui.display_info(f"\nAnalyzing {len(secrets)} secrets with GitGuardian API...")

    # Create client and analyzer
    client = create_client_from_config(ctx_obj.config)
    analyzer = MachineSecretAnalyzer(client)

    # Run analysis
    result = analyzer.analyze(secrets)

    # Run HMSL check and merge results
    if show_progress:
        ui.display_info("Checking secrets against HasMySecretLeaked...")

    leaked_info = check_leaks(ctx, secrets, full_hashes=full_hashes)
    _merge_hmsl_results(secrets, result, leaked_info)

    leaked_count = sum(1 for a in result.analyzed_secrets if a.hmsl_leaked)
    if leaked_count > 0:
        ui.display_warning(f"Found {leaked_count} leaked secrets!")

    # Display results
    display_analyzed_results(
        result,
        json_output=ctx_obj.use_json,
        verbose=ui.is_verbose(),
        output_file=output,
        leaked_threshold=leaked_threshold,
    )

    # Return appropriate exit code
    if result.detected_count > 0:
        return ExitCode.SCAN_FOUND_PROBLEMS
    return ExitCode.SUCCESS
