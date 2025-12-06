"""
Machine check command - scans local machine for secrets and checks them against HMSL.

This command gathers secrets and checks them against HasMySecretLeaked.
Only hashes are sent, not the actual secret values.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, List, Tuple

import click

from ggshield.cmd.machine.common_options import hmsl_options, machine_scan_options

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
from ggshield.verticals.machine.output import display_hmsl_check_results
from ggshield.verticals.machine.secret_gatherer import (
    GatheringConfig,
    MachineSecretGatherer,
)
from ggshield.verticals.machine.sources import GatheredSecret


if TYPE_CHECKING:
    pass


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


def check_secrets(
    ctx: click.Context,
    secrets: List[GatheredSecret],
    full_hashes: bool = False,
) -> Tuple[set, PreparedSecrets]:
    """
    Check secrets against HMSL and return leaked keys.

    Returns:
        Tuple of (leaked_keys set, prepared_data for mapping)
    """
    from ggshield.verticals.hmsl.client import HMSLClient
    from ggshield.verticals.hmsl.utils import get_client

    prepared_data = _prepare_secrets_for_hmsl(secrets)

    # Get HMSL client and check
    ctx_obj = ContextObj.get(ctx)
    hmsl_client: HMSLClient = get_client(ctx_obj.config, ctx.command_path)

    # Query HMSL
    found_secrets = hmsl_client.check(prepared_data.payload, full_hashes=full_hashes)

    # Extract leaked keys
    leaked_keys: set = set()
    for secret in found_secrets:
        name = prepared_data.mapping.get(secret.hash)
        if name:
            leaked_keys.add(name)

    return leaked_keys, prepared_data


@click.command()
@click.pass_context
@add_common_options()
@text_json_format_option
@json_option
@hmsl_options
@machine_scan_options
def check_cmd(
    ctx: click.Context,
    full_hashes: bool,
    timeout: int,
    min_chars: int,
    exclude: Tuple[str, ...],
    ignore_config_exclusions: bool,
    **kwargs: Any,
) -> int:
    """
    Scan for secrets and check if any have been publicly exposed.

    This command gathers potential secrets from your local machine and checks
    them against GitGuardian's HasMySecretLeaked service. Only cryptographic
    hashes are sent to the API, not the actual secret values.

    \b
    Sources scanned:
      - Environment variables
      - GitHub CLI token (if `gh` is installed)
      - ~/.npmrc configuration
      - .env* files (recursive scan from home directory)
      - Private key files (SSH, SSL, crypto keys)

    \b
    Examples:
      ggshield machine check              # Check all secrets
      ggshield machine check --full-hashes  # More accurate check (uses credits)
      ggshield machine check --json       # JSON output
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

    if show_progress:
        ui.display_info(
            f"\nChecking {len(secrets)} secrets against HasMySecretLeaked..."
        )

    # Check secrets against HMSL
    leaked_keys, prepared_data = check_secrets(ctx, secrets, full_hashes=full_hashes)

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
