"""
Output formatting for machine scan results.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import click

from ggshield.core import ui
from ggshield.core.text_utils import pluralize, translate_validity
from ggshield.verticals.machine.secret_gatherer import GatheringStats
from ggshield.verticals.machine.sources import GatheredSecret, SourceType


if TYPE_CHECKING:
    from ggshield.verticals.machine.analyzer import AnalysisResult


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


# --------------------------------------------------------------------------
# Analysis output functions (for --analyze flag)
# --------------------------------------------------------------------------


def display_analyzed_results(
    result: AnalysisResult,
    json_output: bool = False,
    verbose: bool = False,
    output_file: Optional[Path] = None,
) -> None:
    """
    Display analysis results from GitGuardian API.

    Args:
        result: Analysis result containing analyzed secrets
        json_output: If True, output JSON to stdout
        verbose: If True, show per-secret details in text mode
        output_file: If provided, write detailed JSON to this file
    """
    # Write to file if requested (always JSON)
    if output_file:
        json_data = _build_analysis_json(result)
        output_file.write_text(json.dumps(json_data, indent=2))
        ui.display_info(f"Detailed results written to {output_file}")

    # Display to stdout
    if json_output:
        _display_json_analyzed_results(result)
    elif verbose:
        _display_verbose_analyzed_results(result)
    else:
        _display_text_analyzed_results(result)


def _display_text_analyzed_results(result: AnalysisResult) -> None:
    """Display analysis results as summary text."""
    total = len(result.analyzed_secrets)
    detected = result.detected_count

    ui.display_heading(f"Analysis Results: {total} {pluralize('secret', total)} analyzed")

    if result.errors:
        for error in result.errors:
            ui.display_warning(f"  {error}")
        ui.display_info("")

    if total == 0:
        ui.display_info("No secrets to analyze.")
        return

    # Check if we have HMSL results
    has_hmsl = any(s.hmsl_leaked is not None for s in result.analyzed_secrets)
    leaked_secrets = [s for s in result.analyzed_secrets if s.hmsl_leaked]

    # Show counts by detector type
    counts = result.get_counts_by_detector()
    if counts:
        ui.display_info("")
        ui.display_info("By detector type:")
        for detector, stats in sorted(counts.items(), key=lambda x: -x[1]["count"]):
            count = stats["count"]
            valid = stats["valid"]
            invalid = stats["invalid"]

            # Build validity info
            validity_parts = []
            if valid > 0:
                validity_parts.append(f"{valid} valid")
            if invalid > 0:
                validity_parts.append(f"{invalid} invalid")

            if validity_parts:
                validity_str = f" ({', '.join(validity_parts)})"
            else:
                validity_str = ""

            ui.display_info(f"  {detector}: {count}{validity_str}")

    # Show known secrets count
    known = result.known_secrets_count
    if known > 0:
        ui.display_info("")
        ui.display_info(f"Known secrets: {known} (already tracked in dashboard)")

    # Show undetected count
    undetected = total - detected
    if undetected > 0:
        ui.display_info("")
        ui.display_info(f"Unidentified: {undetected} (not recognized as known secret types)")

    # Show leaked secrets if HMSL was run
    if has_hmsl:
        ui.display_info("")
        if leaked_secrets:
            ui.display_warning(f"LEAKED SECRETS: {len(leaked_secrets)} (require immediate action!)")
            for secret in leaked_secrets:
                metadata = secret.gathered_secret.metadata
                detector = secret.detector_display_name or secret.detector_name or "Unknown"
                ui.display_warning(f"  > {detector}: {metadata.source_path}:{metadata.secret_name}")
        else:
            ui.display_info("No leaked secrets found in public data.")

    ui.display_info("")


def _display_verbose_analyzed_results(result: AnalysisResult) -> None:
    """Display detailed per-secret analysis results."""
    total = len(result.analyzed_secrets)
    ui.display_heading(f"Analysis Results: {total} {pluralize('secret', total)} analyzed")

    if result.errors:
        for error in result.errors:
            ui.display_warning(f"  {error}")
        ui.display_info("")

    if total == 0:
        ui.display_info("No secrets to analyze.")
        return

    ui.display_info("")

    for i, secret in enumerate(result.analyzed_secrets, 1):
        metadata = secret.gathered_secret.metadata

        # Header with detector, validity, and leaked status
        if secret.is_detected:
            detector = secret.detector_display_name or secret.detector_name or "Unknown"
            validity = translate_validity(secret.validity).upper() if secret.validity else ""
            if validity:
                header = f"{i}. {detector} [{validity}]"
            else:
                header = f"{i}. {detector}"
        else:
            header = f"{i}. Unidentified secret"

        # Add leaked warning if applicable
        if secret.hmsl_leaked:
            header += " - LEAKED!"

        ui.display_info(header)

        # Location
        location = f"{metadata.source_path}:{metadata.secret_name}"
        ui.display_info(f"   Location: {location}")

        # Known status
        if secret.known_secret:
            if secret.incident_url:
                ui.display_info(f"   Known: Yes - {secret.incident_url}")
            else:
                ui.display_info("   Known: Yes (tracked in dashboard)")
        else:
            ui.display_info("   Known: No")

        # Leaked status if HMSL was run
        if secret.hmsl_leaked is not None:
            if secret.hmsl_leaked:
                ui.display_warning("   Leaked: YES (found in public data)")
            else:
                ui.display_info("   Leaked: No")

        ui.display_info("")


def _display_json_analyzed_results(result: AnalysisResult) -> None:
    """Display analysis results as JSON to stdout."""
    json_data = _build_analysis_json(result)
    click.echo(json.dumps(json_data, indent=2))


def _build_analysis_json(result: AnalysisResult) -> Dict[str, Any]:
    """Build JSON representation of analysis results."""
    # Check if HMSL results are included
    has_hmsl = any(s.hmsl_leaked is not None for s in result.analyzed_secrets)
    leaked_count = sum(1 for s in result.analyzed_secrets if s.hmsl_leaked) if has_hmsl else None

    secrets_data = []
    for secret in result.analyzed_secrets:
        metadata = secret.gathered_secret.metadata
        secret_data: Dict[str, Any] = {
            "detector": secret.detector_display_name,
            "detector_name": secret.detector_name,
            "validity": secret.validity,
            "known_secret": secret.known_secret,
            "incident_url": secret.incident_url,
            "source": {
                "type": metadata.source_type.name,
                "path": metadata.source_path,
                "name": metadata.secret_name,
            },
            # GIM-compatible fields (always included for future inventory uploads)
            "gim": {
                "kind": {
                    "type": "string",
                    "raw": {
                        "hash": secret.gim_hash,
                        "length": secret.gim_length,
                    },
                },
                "sub_path": metadata.secret_name,
            },
        }
        # Include leaked status if HMSL was run
        if secret.hmsl_leaked is not None:
            secret_data["leaked"] = secret.hmsl_leaked
        secrets_data.append(secret_data)

    result_data: Dict[str, Any] = {
        "secrets_analyzed": len(result.analyzed_secrets),
        "detected_count": result.detected_count,
        "known_secrets_count": result.known_secrets_count,
        "fetched_at": result.fetched_at,
        "by_detector": result.get_counts_by_detector(),
        "errors": result.errors,
        "secrets": secrets_data,
    }

    # Include leaked count if HMSL was run
    if leaked_count is not None:
        result_data["leaked_count"] = leaked_count

    return result_data
