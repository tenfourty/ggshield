"""
Output formatting for machine scan results.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

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


def _detector_sort_key(item: Tuple[str, Dict[str, int]]) -> Tuple[int, int]:
    """Sort by count descending, with Unidentified always last."""
    detector, stats = item
    if detector == "Unidentified":
        return (1, 0)  # Always last
    return (0, -stats["count"])  # By count descending


def _build_validity_string(valid: int, invalid: int) -> str:
    """Build validity summary string like '(2 valid, 1 invalid)'."""
    parts = []
    if valid > 0:
        parts.append(f"{valid} valid")
    if invalid > 0:
        parts.append(f"{invalid} invalid")
    return f" ({', '.join(parts)})" if parts else ""


def _display_errors(errors: List[str]) -> None:
    """Display error warnings with indentation."""
    if errors:
        for error in errors:
            ui.display_warning(f"  {error}")
        ui.display_info("")


def _count_leaked_secrets(secrets: List[GatheredSecret], leaked_keys: set) -> int:
    """Count how many secrets are in the leaked keys set."""
    return sum(
        1
        for s in secrets
        if f"{s.metadata.secret_name} ({s.metadata.source_path})" in leaked_keys
    )


def _display_hmsl_header(leaked_count: int, total: int) -> None:
    """Display HMSL check result header."""
    if leaked_count > 0:
        ui.display_warning(
            f"Found {leaked_count} leaked {pluralize('secret', leaked_count)} "
            f"out of {total} checked."
        )
    else:
        ui.display_heading(f"All right! No leaked secrets found ({total} checked).")


def _display_source_summary(counts: Dict[SourceType, int]) -> None:
    """Display source type counts sorted by count descending."""
    for source_type, count in sorted(counts.items(), key=lambda x: -x[1]):
        label = SOURCE_LABELS.get(source_type, source_type.name)
        ui.display_info(f"  {label}: {count}")


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
    verbose: bool = False,
) -> None:
    """Display scan results summary."""
    if json_output:
        _display_json_results(secrets)
    elif verbose:
        _display_verbose_text_results(secrets)
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
        _display_source_summary(counts)

    ui.display_info("")
    ui.display_info("Use --check to verify if any secrets have been publicly exposed.")


def _display_verbose_text_results(secrets: List[GatheredSecret]) -> None:
    """Display verbose results with individual secrets grouped by source."""
    counts = _group_by_source(secrets)

    total = len(secrets)
    ui.display_heading(f"Found {total} potential {pluralize('secret', total)}")

    # Summary section
    if counts:
        ui.display_info("")
        ui.display_info("── Summary ──")
        _display_source_summary(counts)

    # Details section - group by source type
    ui.display_info("")
    ui.display_info("── Details ──")

    # Sort secrets by source type (same order as summary)
    source_order = {
        st: idx
        for idx, st in enumerate(sorted(counts.keys(), key=lambda st: -counts[st]))
    }
    sorted_secrets = sorted(
        secrets, key=lambda s: source_order.get(s.metadata.source_type, 999)
    )

    current_source = None
    for i, secret in enumerate(sorted_secrets, 1):
        metadata = secret.metadata

        # Add section header when source type changes
        if metadata.source_type != current_source:
            current_source = metadata.source_type
            label = SOURCE_LABELS.get(current_source, current_source.name)
            ui.display_info("")
            ui.display_info(f"  [{label}]")

        ui.display_info(f"  {i}. {metadata.source_path}:{metadata.secret_name}")

    ui.display_info("")
    ui.display_info("Use --analyze to identify secret types and validity.")
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

    ui.display_heading(
        f"Analysis Results: {total} {pluralize('secret', total)} analyzed"
    )

    _display_errors(result.errors)

    if total == 0:
        ui.display_info("No secrets to analyze.")
        return

    # Check if we have HMSL results
    has_hmsl = any(s.hmsl_leaked is not None for s in result.analyzed_secrets)
    leaked_secrets = [s for s in result.analyzed_secrets if s.hmsl_leaked]

    # Show counts by detector type (Unidentified always last)
    counts = result.get_counts_by_detector()

    if counts:
        ui.display_info("")
        ui.display_info("By detector type:")
        for detector, stats in sorted(counts.items(), key=_detector_sort_key):
            count = stats["count"]
            validity_str = _build_validity_string(stats["valid"], stats["invalid"])
            ui.display_info(f"  {detector}: {count}{validity_str}")

    # Show known secrets count
    known = result.known_secrets_count
    if known > 0:
        ui.display_info("")
        ui.display_info(f"Known secrets: {known} (already tracked in dashboard)")

    # Show leaked secrets if HMSL was run
    if has_hmsl:
        ui.display_info("")
        if leaked_secrets:
            ui.display_warning(
                f"LEAKED SECRETS: {len(leaked_secrets)} (require immediate action!)"
            )
            for secret in leaked_secrets:
                metadata = secret.gathered_secret.metadata
                ui.display_warning(
                    f"  > {secret.get_display_name()}: {metadata.source_path}:{metadata.secret_name}"
                )
        else:
            ui.display_info("No leaked secrets found in public data.")

    ui.display_info("")


def _display_verbose_analyzed_results(result: AnalysisResult) -> None:
    """Display detailed per-secret analysis results with summary."""
    total = len(result.analyzed_secrets)

    ui.display_heading(
        f"Analysis Results: {total} {pluralize('secret', total)} analyzed"
    )

    _display_errors(result.errors)

    if total == 0:
        ui.display_info("No secrets to analyze.")
        return

    # Check if we have HMSL results
    has_hmsl = any(s.hmsl_leaked is not None for s in result.analyzed_secrets)
    leaked_secrets = [s for s in result.analyzed_secrets if s.hmsl_leaked]

    # ─── Summary Section ───
    ui.display_info("")
    ui.display_info("── Summary ──")

    # Show counts by detector type (Unidentified always last)
    counts = result.get_counts_by_detector()

    if counts:
        for detector, stats in sorted(counts.items(), key=_detector_sort_key):
            count = stats["count"]
            validity_str = _build_validity_string(stats["valid"], stats["invalid"])
            ui.display_info(f"  {detector}: {count}{validity_str}")

    # Show known secrets count
    known = result.known_secrets_count
    if known > 0:
        ui.display_info(f"  Known secrets: {known} (already tracked in dashboard)")

    # Show leaked status
    if has_hmsl:
        if leaked_secrets:
            ui.display_warning(
                f"  LEAKED: {len(leaked_secrets)} secrets found in public data!"
            )
        else:
            ui.display_info("  Leaked: None found in public data")

    # ─── Details Section ───
    ui.display_info("")
    ui.display_info("── Details ──")

    # Sort secrets by detector type in same order as summary (Unidentified last)
    sorted_detectors = sorted(
        counts.keys(), key=lambda d: (d == "Unidentified", -counts[d]["count"])
    )
    detector_order = {detector: idx for idx, detector in enumerate(sorted_detectors)}

    sorted_secrets = sorted(
        result.analyzed_secrets,
        key=lambda s: detector_order.get(s.get_display_name(), 999),
    )

    current_detector = None
    for i, secret in enumerate(sorted_secrets, 1):
        metadata = secret.gathered_secret.metadata
        detector = secret.get_display_name()

        # Add section header when detector type changes
        if detector != current_detector:
            current_detector = detector
            ui.display_info("")
            ui.display_info(f"  [{detector}]")

        # Build compact line: number, validity, path:name, flags
        if secret.is_detected and secret.validity:
            validity = translate_validity(secret.validity).upper()
            line = f"  {i}. [{validity}] {metadata.source_path}:{metadata.secret_name}"
        else:
            line = f"  {i}. {metadata.source_path}:{metadata.secret_name}"

        # Add flags
        if secret.hmsl_leaked:
            line += " - LEAKED!"
        if secret.known_secret:
            line += " (known)"

        ui.display_info(line)


def _display_json_analyzed_results(result: AnalysisResult) -> None:
    """Display analysis results as JSON to stdout."""
    json_data = _build_analysis_json(result)
    click.echo(json.dumps(json_data, indent=2))


def _build_analysis_json(result: AnalysisResult) -> Dict[str, Any]:
    """Build JSON representation of analysis results."""
    # Check if HMSL results are included
    has_hmsl = any(s.hmsl_leaked is not None for s in result.analyzed_secrets)
    leaked_count = (
        sum(1 for s in result.analyzed_secrets if s.hmsl_leaked) if has_hmsl else None
    )

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


# --------------------------------------------------------------------------
# HMSL check-only output functions (for --check without --analyze)
# --------------------------------------------------------------------------


def display_hmsl_check_results(
    secrets: List[GatheredSecret],
    leaked_keys: set,
    json_output: bool = False,
    verbose: bool = False,
) -> None:
    """
    Display HMSL check results for machine scan.

    Args:
        secrets: Original gathered secrets
        leaked_keys: Set of keys (name + path) that were found leaked
        json_output: If True, output JSON
        verbose: If True, show per-secret details
    """
    if json_output:
        _display_json_hmsl_results(secrets, leaked_keys)
    elif verbose:
        _display_verbose_hmsl_results(secrets, leaked_keys)
    else:
        _display_text_hmsl_results(secrets, leaked_keys)


def _display_text_hmsl_results(
    secrets: List[GatheredSecret],
    leaked_keys: set,
) -> None:
    """Display HMSL check summary."""
    total = len(secrets)
    leaked_count = _count_leaked_secrets(secrets, leaked_keys)

    _display_hmsl_header(leaked_count, total)

    ui.display_info("")
    ui.display_info("Use --verbose to see all checked secrets.")


def _display_verbose_hmsl_results(
    secrets: List[GatheredSecret],
    leaked_keys: set,
) -> None:
    """Display verbose HMSL check results with per-secret details."""
    total = len(secrets)

    # Count by source type
    counts = _group_by_source(secrets)
    leaked_count = _count_leaked_secrets(secrets, leaked_keys)

    _display_hmsl_header(leaked_count, total)

    # Summary section
    ui.display_info("")
    ui.display_info("── Summary ──")
    _display_source_summary(counts)

    # Details section
    ui.display_info("")
    ui.display_info("── Details ──")

    # Sort secrets by source type (same order as summary)
    source_order = {
        st: idx
        for idx, st in enumerate(sorted(counts.keys(), key=lambda st: -counts[st]))
    }
    sorted_secrets = sorted(
        secrets, key=lambda s: source_order.get(s.metadata.source_type, 999)
    )

    current_source = None
    for i, secret in enumerate(sorted_secrets, 1):
        metadata = secret.metadata

        # Add section header when source type changes
        if metadata.source_type != current_source:
            current_source = metadata.source_type
            label = SOURCE_LABELS.get(current_source, current_source.name)
            ui.display_info("")
            ui.display_info(f"  [{label}]")

        # Check if leaked
        key = f"{metadata.secret_name} ({metadata.source_path})"
        is_leaked = key in leaked_keys

        if is_leaked:
            ui.display_warning(
                f"  {i}. [LEAKED] {metadata.source_path}:{metadata.secret_name}"
            )
        else:
            ui.display_info(
                f"  {i}. [OK] {metadata.source_path}:{metadata.secret_name}"
            )


def _display_json_hmsl_results(
    secrets: List[GatheredSecret],
    leaked_keys: set,
) -> None:
    """Display HMSL check results as JSON."""
    secrets_data = []
    for secret in secrets:
        metadata = secret.metadata
        key = f"{metadata.secret_name} ({metadata.source_path})"
        secrets_data.append(
            {
                "source": {
                    "type": metadata.source_type.name,
                    "path": metadata.source_path,
                    "name": metadata.secret_name,
                },
                "leaked": key in leaked_keys,
            }
        )

    leaked_count = sum(1 for s in secrets_data if s["leaked"])
    data = {
        "secrets_checked": len(secrets),
        "leaked_count": leaked_count,
        "secrets": secrets_data,
    }
    click.echo(json.dumps(data, indent=2))
