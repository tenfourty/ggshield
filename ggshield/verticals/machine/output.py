"""
Output formatting for machine scan results.
"""

import json
from typing import Dict, List

import click

from ggshield.core import ui
from ggshield.core.text_utils import pluralize
from ggshield.verticals.machine.secret_gatherer import GatheringStats
from ggshield.verticals.machine.sources import GatheredSecret, SourceType


# Human-readable labels for source types
SOURCE_LABELS: Dict[SourceType, str] = {
    SourceType.ENVIRONMENT_VAR: "Environment variables",
    SourceType.GITHUB_TOKEN: "GitHub token",
    SourceType.NPMRC: "NPM configuration",
    SourceType.ENV_FILE: "Environment files",
    SourceType.PRIVATE_KEY: "Private keys",
}


def display_gathering_stats(stats: GatheringStats, json_output: bool = False) -> None:
    """Display statistics from the gathering process."""
    if json_output:
        return

    ui.display_info("")
    ui.display_info("Sources scanned:")
    ui.display_info(f"  Environment variables: {stats.env_vars_count}")
    ui.display_info(
        f"  GitHub token: {'found' if stats.github_token_found else 'not found'}"
    )

    if stats.npmrc_files > 0:
        ui.display_info(
            f"  NPM configuration: {stats.npmrc_files} file, "
            f"{stats.npmrc_secrets} {pluralize('secret', stats.npmrc_secrets)}"
        )
    else:
        ui.display_info("  NPM configuration: no .npmrc found")

    ui.display_info(
        f"  Environment files: {stats.env_files} {pluralize('file', stats.env_files)}, "
        f"{stats.env_secrets} {pluralize('secret', stats.env_secrets)}"
    )
    ui.display_info(
        f"  Private keys: {stats.private_key_files} {pluralize('file', stats.private_key_files)}"
    )

    if stats.total_files_visited > 0:
        ui.display_info(
            f"  Total files visited: {stats.total_files_visited} "
            f"({stats.elapsed_seconds:.1f}s)"
        )

    if stats.timed_out:
        ui.display_warning(
            "Scan timed out. Some files may not have been scanned. "
            "Use --timeout to increase the limit."
        )
    ui.display_info("")


def display_scan_results(
    secrets: List[GatheredSecret],
    json_output: bool = False,
) -> None:
    """Display scan results summary."""
    if json_output:
        _display_json_results(secrets)
    else:
        _display_text_results(secrets)


def _group_by_source(secrets: List[GatheredSecret]) -> Dict[SourceType, int]:
    """Group secrets by source type and count them."""
    counts: Dict[SourceType, int] = {}
    for secret in secrets:
        source_type = secret.metadata.source_type
        counts[source_type] = counts.get(source_type, 0) + 1
    return counts


def _display_json_results(secrets: List[GatheredSecret]) -> None:
    """Display results in JSON format."""
    counts = _group_by_source(secrets)

    data = {
        "secrets_found": len(secrets),
        "sources": {
            SOURCE_LABELS.get(source_type, source_type.name): count
            for source_type, count in counts.items()
        },
    }

    click.echo(json.dumps(data, indent=2))


def _display_text_results(secrets: List[GatheredSecret]) -> None:
    """Display results in text format."""
    counts = _group_by_source(secrets)

    total = len(secrets)
    ui.display_heading(f"Found {total} potential {pluralize('secret', total)}")

    if counts:
        ui.display_info("")
        ui.display_info("By source:")
        for source_type, count in sorted(counts.items(), key=lambda x: -x[1]):
            label = SOURCE_LABELS.get(source_type, source_type.name)
            ui.display_info(f"  {label}: {count}")

    ui.display_info("")
    ui.display_info("Use --check to verify if any secrets have been publicly exposed.")
