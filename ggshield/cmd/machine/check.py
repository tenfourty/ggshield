"""
Machine check command - scans local machine for secrets and checks them against HMSL.

This command gathers secrets and checks them against HasMySecretLeaked.
Only hashes are sent, not the actual secret values.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Dict, List, Tuple

import click
from pygitguardian.models import TokenScope

from pathlib import Path

from ggshield.cmd.machine.common_options import (
    FULL_DISK_DEFAULT_TIMEOUT,
    hmsl_options,
    machine_scan_options,
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
from ggshield.core.client import check_client_api_key, create_client_from_config
from ggshield.core.errors import ExitCode
from ggshield.core.filter import init_exclusion_regexes
from ggshield.verticals.hmsl.collection import (
    NAMING_STRATEGIES,
    PreparedSecrets,
    SecretWithKey,
    prepare,
)
from ggshield.verticals.machine.output import (
    LeakedSecretInfo,
    display_hmsl_check_results,
)
from ggshield.verticals.machine.secret_gatherer import (
    GatheringConfig,
    MachineSecretGatherer,
    ScanMode,
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
) -> Tuple[Dict[str, LeakedSecretInfo], PreparedSecrets]:
    """
    Check secrets against HMSL and return leaked secret info.

    Returns:
        Tuple of (leaked_info dict mapping key -> LeakedSecretInfo, prepared_data)
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

    return leaked_info, prepared_data


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
    leaked_threshold: int,
    timeout: int,
    min_chars: int,
    exclude: Tuple[str, ...],
    ignore_config_exclusions: bool,
    deep: bool,
    path: Path | None,
    full_disk: bool,
    **kwargs: Any,
) -> int:
    """
    Scan for secrets and check if any have been publicly exposed.

    [Alpha] This command is under active development and may change.

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
    With --deep flag:
      - Sends config files (.json, .yaml, etc.) to GitGuardian API
      - Uses 500+ secret detectors for comprehensive scanning
      - Found secrets are also checked against HMSL

    \b
    Examples:
      ggshield machine check              # Check all secrets
      ggshield machine check --deep       # Include API-based deep scan
      ggshield machine check --full-hashes  # More accurate check (uses credits)
      ggshield machine check --json       # JSON output
    """
    ctx_obj = ContextObj.get(ctx)

    # Validate mutually exclusive options
    if path is not None and full_disk:
        raise click.UsageError("--path and --full-disk are mutually exclusive.")

    # Determine scan mode and effective timeout
    if full_disk:
        scan_mode = ScanMode.FULL_DISK
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

    # Gather secrets with progress reporting
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
    leaked_info, prepared_data = check_secrets(ctx, secrets, full_hashes=full_hashes)

    # Display results
    display_hmsl_check_results(
        secrets,
        leaked_info,
        json_output=ctx_obj.use_json,
        verbose=ui.is_verbose(),
        leaked_threshold=leaked_threshold,
    )

    # Return appropriate exit code
    if leaked_info:
        return ExitCode.SCAN_FOUND_PROBLEMS
    return ExitCode.SUCCESS
