"""
Output formatting for machine scan results.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

import click

from ggshield.core import ui
from ggshield.core.text_utils import pluralize, translate_validity
from ggshield.verticals.machine.secret_gatherer import GatheringStats
from ggshield.verticals.machine.sources import GatheredSecret, SourceType


# Priority tier thresholds for leaked secrets
HIGH_PRIORITY_THRESHOLD = 10  # <10 occurrences = high priority
MEDIUM_PRIORITY_THRESHOLD = 100  # 10-99 occurrences = medium priority
# >= 100 = hidden by default (likely false positives)


@dataclass
class LeakedSecretInfo:
    """Information about a leaked secret from HMSL."""

    key: str  # The secret key (name + path)
    count: int  # Number of occurrences found in public data
    url: Optional[str]  # URL where it was found (if available)
    secret_value: str  # The actual secret value (safe to show since it's public)


if TYPE_CHECKING:
    from ggshield.verticals.machine.analyzer import AnalysisResult, AnalyzedSecret


# Human-readable labels for source types
SOURCE_LABELS: Dict[SourceType, str] = {
    SourceType.ENVIRONMENT_VAR: "Environment variables",
    SourceType.GITHUB_TOKEN: "GitHub token",
    SourceType.NPMRC: "NPM configuration",
    SourceType.ENV_FILE: "Environment files",
    SourceType.PRIVATE_KEY: "Private keys",
    # Cloud providers
    SourceType.AWS_CREDENTIALS: "AWS credentials",
    SourceType.KUBERNETES_CONFIG: "Kubernetes config",
    # Container registries
    SourceType.DOCKER_CONFIG: "Docker config",
    # Package registries
    SourceType.PYPIRC: "PyPI config",
    SourceType.CARGO_CREDENTIALS: "Cargo credentials",
    SourceType.GEM_CREDENTIALS: "RubyGems credentials",
    # Other credential files
    SourceType.VAULT_TOKEN: "Vault token",
    SourceType.NETRC: "Netrc",
    SourceType.GIT_CREDENTIALS: "Git credentials",
    # Cloud providers (additional)
    SourceType.GCP_ADC: "GCP credentials",
    SourceType.AZURE_CLI: "Azure CLI",
    # Package managers (additional)
    SourceType.COMPOSER_AUTH: "Composer auth",
    SourceType.HELM_CONFIG: "Helm config",
    SourceType.GRADLE_PROPERTIES: "Gradle properties",
    # CI/CD platforms
    SourceType.CIRCLECI_CONFIG: "CircleCI config",
    SourceType.GITLAB_CLI: "GitLab CLI",
    SourceType.TRAVIS_CI_CONFIG: "Travis CI config",
    # Databases
    SourceType.PGPASS: "PostgreSQL pgpass",
    SourceType.MYSQL_CONFIG: "MySQL config",
    # AI coding tools
    SourceType.CLAUDE_CODE: "Claude Code",
    SourceType.GEMINI_CLI: "Gemini CLI",
    SourceType.AIDER_CONFIG: "Aider config",
    SourceType.CONTINUE_CONFIG: "Continue config",
    # Messaging
    SourceType.SLACK_CREDENTIALS: "Slack credentials",
    # Generic credential files
    SourceType.GENERIC_CREDENTIAL: "Generic credentials",
    # Deep scan (API-based)
    SourceType.DEEP_SCAN: "Deep scan (API)",
    # Desktop apps
    SourceType.RAYCAST_CONFIG: "Raycast config",
    SourceType.JOPLIN_CONFIG: "Joplin config",
    SourceType.FACTORY_AUTH: "Factory CLI auth",
}


def _get_group_priority(group_name: str) -> int:
    """
    Get sort priority for a group name.

    Returns priority (higher = later in list):
    0: Specific detector types
    1: Generic Private Key, Base64 Generic Private Key
    2: Generic High Entropy Secret (most generic, least actionable)
    """
    if group_name == "Generic High Entropy Secret":
        return 2
    if group_name in ("Generic Private Key", "Base64 Generic Private Key"):
        return 1
    return 0


def _detector_sort_key(item: Tuple[str, Dict[str, int]]) -> Tuple[int, int]:
    """Sort by count descending, with generic types at the bottom."""
    detector, stats = item
    return (_get_group_priority(detector), -stats["count"])


def _get_group_name(secret: "AnalyzedSecret") -> str:
    """
    Get the grouping name for a secret in output.

    For secrets identified by the API, uses the detector display name.
    For unidentified secrets, uses the source type label (e.g., "Raycast config")
    instead of lumping them all under "Unidentified".
    """
    if secret.is_detected:
        return secret.get_display_name()
    # For unidentified secrets, group by source type
    source_type = secret.gathered_secret.metadata.source_type
    return SOURCE_LABELS.get(source_type, source_type.name)


def _build_counts_by_group(
    secrets: List["AnalyzedSecret"],
) -> Dict[str, Dict[str, int]]:
    """
    Build counts grouped by detector type or source type.

    Unlike AnalysisResult.get_counts_by_detector(), this uses source type labels
    for unidentified secrets instead of lumping them all under "Unidentified".
    """
    counts: Dict[str, Dict[str, int]] = {}

    for secret in secrets:
        group = _get_group_name(secret)

        if group not in counts:
            counts[group] = {"count": 0, "valid": 0, "invalid": 0, "unknown": 0}

        counts[group]["count"] += 1

        validity = secret.validity or "unknown"
        if validity in ("valid", "invalid"):
            counts[group][validity] += 1
        else:
            counts[group]["unknown"] += 1

    return counts


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


def _count_leaked_secrets(
    secrets: List[GatheredSecret], leaked_info: Dict[str, LeakedSecretInfo]
) -> int:
    """Count how many secrets are in the leaked info dict."""
    return sum(
        1
        for s in secrets
        if f"{s.metadata.secret_name} ({s.metadata.source_path})" in leaked_info
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


def _get_priority_tier(occurrences: int) -> str:
    """Get the priority tier for a leaked secret based on occurrence count."""
    if occurrences < HIGH_PRIORITY_THRESHOLD:
        return "high"
    elif occurrences < MEDIUM_PRIORITY_THRESHOLD:
        return "medium"
    else:
        return "hidden"


def _group_leaked_by_priority(
    leaked_info: Dict[str, LeakedSecretInfo],
    threshold: int,
) -> Tuple[List[LeakedSecretInfo], List[LeakedSecretInfo], List[LeakedSecretInfo]]:
    """
    Group leaked secrets by priority tier.

    Returns:
        Tuple of (high_priority, medium_priority, hidden) lists.
        Secrets are sorted by occurrence count within each tier.
    """
    high: List[LeakedSecretInfo] = []
    medium: List[LeakedSecretInfo] = []
    hidden: List[LeakedSecretInfo] = []

    for info in leaked_info.values():
        if threshold > 0 and info.count >= threshold:
            hidden.append(info)
        elif info.count < HIGH_PRIORITY_THRESHOLD:
            high.append(info)
        else:
            medium.append(info)

    # Sort each tier by count ascending (lowest/most urgent first)
    high.sort(key=lambda x: x.count)
    medium.sort(key=lambda x: x.count)
    hidden.sort(key=lambda x: x.count)

    return high, medium, hidden


def display_gathering_stats(stats: GatheringStats, json_output: bool = False) -> None:
    """Display statistics from the gathering process."""
    if json_output:
        return

    ui.display_info("")
    ui.display_info("Sources scanned:")
    ui.display_info(
        f"  Environment variables: {stats.get_secrets(SourceType.ENVIRONMENT_VAR)}"
    )
    ui.display_info(
        f"  GitHub token: {'found' if stats.github_token_found else 'not found'}"
    )

    npmrc_files = stats.get_files(SourceType.NPMRC)
    npmrc_secrets = stats.get_secrets(SourceType.NPMRC)
    if npmrc_files > 0:
        ui.display_info(
            f"  NPM configuration: {npmrc_files} file, "
            f"{npmrc_secrets} {pluralize('secret', npmrc_secrets)}"
        )
    else:
        ui.display_info("  NPM configuration: no .npmrc found")

    env_files = stats.get_files(SourceType.ENV_FILE)
    env_secrets = stats.get_secrets(SourceType.ENV_FILE)
    ui.display_info(
        f"  Environment files: {env_files} {pluralize('file', env_files)}, "
        f"{env_secrets} {pluralize('secret', env_secrets)}"
    )

    key_files = stats.get_files(SourceType.PRIVATE_KEY)
    ui.display_info(f"  Private keys: {key_files} {pluralize('file', key_files)}")

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
    """Group secrets by source type and count them (excludes DEEP_SCAN)."""
    counts: Dict[SourceType, int] = {}
    for secret in secrets:
        source_type = secret.metadata.source_type
        # Skip DEEP_SCAN - these are grouped by detector type instead
        if source_type == SourceType.DEEP_SCAN:
            continue
        counts[source_type] = counts.get(source_type, 0) + 1
    return counts


def _group_deep_scan_by_detector(secrets: List[GatheredSecret]) -> Dict[str, int]:
    """Group DEEP_SCAN secrets by their detector type (stored in secret_name)."""
    counts: Dict[str, int] = {}
    for secret in secrets:
        if secret.metadata.source_type == SourceType.DEEP_SCAN:
            detector_type = secret.metadata.secret_name
            counts[detector_type] = counts.get(detector_type, 0) + 1
    return counts


def _display_json_results(secrets: List[GatheredSecret]) -> None:
    """Display results in JSON format."""
    counts = _group_by_source(secrets)
    deep_scan_counts = _group_deep_scan_by_detector(secrets)

    secrets_data = []
    for secret in secrets:
        metadata = secret.metadata
        # For deep scan secrets, use detector type as the source label
        if metadata.source_type == SourceType.DEEP_SCAN:
            source_label = metadata.secret_name  # This is the detector type
        else:
            source_label = SOURCE_LABELS.get(
                metadata.source_type, metadata.source_type.name
            )
        secrets_data.append(
            {
                "source_type": source_label,
                "source_path": metadata.source_path,
                "secret_name": metadata.secret_name,
                "detector_type": (
                    metadata.secret_name
                    if metadata.source_type == SourceType.DEEP_SCAN
                    else None
                ),
            }
        )

    # Combine source counts with deep scan detector counts
    all_sources = {
        SOURCE_LABELS.get(source_type, source_type.name): count
        for source_type, count in counts.items()
    }
    # Add deep scan detector types to sources
    all_sources.update(deep_scan_counts)

    data = {
        "secrets_found": len(secrets),
        "sources": all_sources,
        "by_detector": deep_scan_counts if deep_scan_counts else None,
        "secrets": secrets_data,
    }

    click.echo(json.dumps(data, indent=2))


def _display_text_results(secrets: List[GatheredSecret]) -> None:
    """Display results in text format."""
    counts = _group_by_source(secrets)
    deep_scan_counts = _group_deep_scan_by_detector(secrets)

    total = len(secrets)
    ui.display_heading(f"Found {total} potential {pluralize('secret', total)}")

    if counts or deep_scan_counts:
        ui.display_info("")
        ui.display_info("── Summary ──")

        # Show deep scan secrets grouped by detector type first (generic types last)
        if deep_scan_counts:
            for detector, count in sorted(
                deep_scan_counts.items(),
                key=lambda x: (_get_group_priority(x[0]), -x[1]),
            ):
                ui.display_info(f"  {detector}: {count}")

        # Then show other source types
        _display_source_summary(counts)

    ui.display_info("")
    ui.display_info(
        "Use `ggshield machine check` to check for public leaks (sends hashes only, not secrets)."
    )
    ui.display_info(
        "Use `ggshield machine analyze` for full analysis with GitGuardian API."
    )


def _display_verbose_text_results(secrets: List[GatheredSecret]) -> None:
    """Display verbose results with individual secrets grouped by source/detector."""
    counts = _group_by_source(secrets)
    deep_scan_counts = _group_deep_scan_by_detector(secrets)

    total = len(secrets)
    ui.display_heading(f"Found {total} potential {pluralize('secret', total)}")

    # Summary section
    if counts or deep_scan_counts:
        ui.display_info("")
        ui.display_info("── Summary ──")

        # Show deep scan secrets grouped by detector type first (generic types last)
        if deep_scan_counts:
            for detector, count in sorted(
                deep_scan_counts.items(),
                key=lambda x: (_get_group_priority(x[0]), -x[1]),
            ):
                ui.display_info(f"  {detector}: {count}")

        # Then show other source types
        _display_source_summary(counts)

    # Details section
    ui.display_info("")
    ui.display_info("── Details ──")

    # Separate deep scan secrets from others
    deep_scan_secrets = [
        s for s in secrets if s.metadata.source_type == SourceType.DEEP_SCAN
    ]
    other_secrets = [
        s for s in secrets if s.metadata.source_type != SourceType.DEEP_SCAN
    ]

    # Sort deep scan secrets by detector type (same order as summary)
    detector_order = {
        dt: idx
        for idx, dt in enumerate(
            sorted(deep_scan_counts.keys(), key=lambda dt: -deep_scan_counts[dt])
        )
    }
    sorted_deep_scan = sorted(
        deep_scan_secrets,
        key=lambda s: detector_order.get(s.metadata.secret_name, 999),
    )

    # Sort other secrets by source type (same order as summary)
    source_order = {
        st: idx
        for idx, st in enumerate(sorted(counts.keys(), key=lambda st: -counts[st]))
    }
    sorted_other = sorted(
        other_secrets, key=lambda s: source_order.get(s.metadata.source_type, 999)
    )

    # Display deep scan secrets first, grouped by detector type
    current_detector = None
    i = 1
    for secret in sorted_deep_scan:
        metadata = secret.metadata
        detector = metadata.secret_name

        # Add section header when detector type changes
        if detector != current_detector:
            current_detector = detector
            ui.display_info("")
            ui.display_info(f"  [{detector}]")

        ui.display_info(f"  {i}. {metadata.source_path}")
        i += 1

    # Display other secrets grouped by source type
    current_source = None
    for secret in sorted_other:
        metadata = secret.metadata

        # Add section header when source type changes
        if metadata.source_type != current_source:
            current_source = metadata.source_type
            label = SOURCE_LABELS.get(current_source, current_source.name)
            ui.display_info("")
            ui.display_info(f"  [{label}]")

        ui.display_info(f"  {i}. {metadata.source_path}:{metadata.secret_name}")
        i += 1

    ui.display_info("")
    ui.display_info(
        "Use `ggshield machine check` to check for public leaks (sends hashes only, not secrets)."
    )
    ui.display_info(
        "Use `ggshield machine analyze` for full analysis with GitGuardian API."
    )


# --------------------------------------------------------------------------
# Analysis output functions (for `machine analyze` command)
# --------------------------------------------------------------------------


def display_analyzed_results(
    result: AnalysisResult,
    json_output: bool = False,
    verbose: bool = False,
    output_file: Optional[Path] = None,
    leaked_threshold: int = 100,
) -> None:
    """
    Display analysis results from GitGuardian API.

    Args:
        result: Analysis result containing analyzed secrets
        json_output: If True, output JSON to stdout
        verbose: If True, show per-secret details in text mode
        output_file: If provided, write detailed JSON to this file
        leaked_threshold: Hide leaked secrets with >= N occurrences (0 = show all)
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
        _display_verbose_analyzed_results(result, leaked_threshold)
    else:
        _display_text_analyzed_results(result, leaked_threshold)


def _display_text_analyzed_results(
    result: AnalysisResult,
    leaked_threshold: int = 100,
) -> None:
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

    # Group leaked by priority
    high_priority = [
        s
        for s in leaked_secrets
        if s.hmsl_occurrences and s.hmsl_occurrences < HIGH_PRIORITY_THRESHOLD
    ]
    medium_priority = [
        s
        for s in leaked_secrets
        if s.hmsl_occurrences
        and HIGH_PRIORITY_THRESHOLD <= s.hmsl_occurrences < leaked_threshold
    ]
    hidden_count = len(leaked_secrets) - len(high_priority) - len(medium_priority)
    if leaked_threshold == 0:
        hidden_count = 0  # Show all when threshold is 0

    # Show counts by detector type, using source type for unidentified secrets
    counts = _build_counts_by_group(result.analyzed_secrets)

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
        visible_leaked = high_priority + medium_priority
        if visible_leaked:
            ui.display_warning(
                f"LEAKED SECRETS: {len(visible_leaked)} (require immediate action!)"
            )
            for secret in visible_leaked:
                metadata = secret.gathered_secret.metadata
                match_name = metadata.match_name
                ui.display_warning(
                    f"  > {_get_group_name(secret)}: {metadata.source_path}:{metadata.secret_name}"
                )
                if match_name:
                    ui.display_warning(f"      Key: {match_name}")
                if secret.hmsl_occurrences:
                    ui.display_warning(f"      Occurrences: {secret.hmsl_occurrences}")
                if secret.hmsl_url:
                    ui.display_warning(f"      First seen: {secret.hmsl_url}")
                # Show the value since it's already public
                ui.display_warning(f"      Value: {secret.gathered_secret.value}")
            if hidden_count > 0:
                ui.display_info(
                    f"\n  Hidden: {hidden_count} secrets (>={leaked_threshold} occurrences, likely false positives)"
                )
        elif hidden_count > 0:
            ui.display_info(
                f"Leaked secrets: {hidden_count} hidden (>={leaked_threshold} occurrences, likely false positives)"
            )
        else:
            ui.display_info("No leaked secrets found in public data.")

    ui.display_info("")


def _display_verbose_analyzed_results(
    result: AnalysisResult,
    leaked_threshold: int = 100,
) -> None:
    """Display detailed per-secret analysis results with summary and priority grouping."""
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
    non_leaked_secrets = [s for s in result.analyzed_secrets if not s.hmsl_leaked]

    # Group leaked by priority
    high_priority = [
        s
        for s in leaked_secrets
        if s.hmsl_occurrences and s.hmsl_occurrences < HIGH_PRIORITY_THRESHOLD
    ]
    medium_priority = [
        s
        for s in leaked_secrets
        if s.hmsl_occurrences
        and HIGH_PRIORITY_THRESHOLD <= s.hmsl_occurrences < leaked_threshold
    ]
    hidden = [
        s
        for s in leaked_secrets
        if leaked_threshold > 0
        and s.hmsl_occurrences
        and s.hmsl_occurrences >= leaked_threshold
    ]
    # Handle secrets with no occurrence count (shouldn't happen but be safe)
    unclassified = [s for s in leaked_secrets if not s.hmsl_occurrences]
    high_priority.extend(unclassified)  # Treat unknown as high priority

    # Sort each tier by occurrence count
    high_priority.sort(key=lambda s: s.hmsl_occurrences or 0)
    medium_priority.sort(key=lambda s: s.hmsl_occurrences or 0)

    # ─── Summary Section ───
    ui.display_info("")
    ui.display_info("── Summary ──")

    # Show counts by detector type, using source type for unidentified secrets
    counts = _build_counts_by_group(result.analyzed_secrets)

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
        visible_leaked = len(high_priority) + len(medium_priority)
        if visible_leaked > 0:
            ui.display_warning(
                f"  LEAKED: {visible_leaked} secrets found in public data!"
            )
        else:
            ui.display_info("  Leaked: None found in public data")
        if len(hidden) > 0:
            ui.display_info(
                f"  Hidden: {len(hidden)} secrets (>={leaked_threshold} occurrences, likely false positives)"
            )

    # ─── Leaked Secrets Section (by priority) ───
    if high_priority or medium_priority:
        ui.display_info("")
        ui.display_info("── Leaked Secrets ──")
        i = 1

        # High priority (< 10 occurrences)
        if high_priority:
            ui.display_info("")
            ui.display_info(
                f"  [HIGH PRIORITY - <{HIGH_PRIORITY_THRESHOLD} occurrences]"
            )
            for secret in high_priority:
                metadata = secret.gathered_secret.metadata
                match_name = metadata.match_name
                source_label = SOURCE_LABELS.get(
                    metadata.source_type, metadata.source_type.name
                )

                # Build line with validity if detected
                if secret.is_detected and secret.validity:
                    validity = translate_validity(secret.validity).upper()
                    line = f"  {i}. [{source_label}] [{validity}] {metadata.source_path}:{metadata.secret_name}"
                else:
                    line = f"  {i}. [{source_label}] {metadata.source_path}:{metadata.secret_name}"

                if secret.known_secret:
                    line += " (known)"

                ui.display_info(line)
                if match_name:
                    ui.display_info(f"       Key: {match_name}")
                if secret.hmsl_occurrences:
                    ui.display_info(f"       Occurrences: {secret.hmsl_occurrences}")
                if secret.hmsl_url:
                    ui.display_info(f"       First seen: {secret.hmsl_url}")
                ui.display_info(f"       Value: {secret.gathered_secret.value}")
                i += 1

        # Medium priority (10-99 occurrences)
        if medium_priority:
            ui.display_info("")
            ui.display_info(
                f"  [MEDIUM PRIORITY - {HIGH_PRIORITY_THRESHOLD}-{MEDIUM_PRIORITY_THRESHOLD - 1} occurrences]"
            )
            for secret in medium_priority:
                metadata = secret.gathered_secret.metadata
                match_name = metadata.match_name
                source_label = SOURCE_LABELS.get(
                    metadata.source_type, metadata.source_type.name
                )

                # Build line with validity if detected
                if secret.is_detected and secret.validity:
                    validity = translate_validity(secret.validity).upper()
                    line = f"  {i}. [{source_label}] [{validity}] {metadata.source_path}:{metadata.secret_name}"
                else:
                    line = f"  {i}. [{source_label}] {metadata.source_path}:{metadata.secret_name}"

                if secret.known_secret:
                    line += " (known)"

                ui.display_info(line)
                if match_name:
                    ui.display_info(f"       Key: {match_name}")
                if secret.hmsl_occurrences:
                    ui.display_info(f"       Occurrences: {secret.hmsl_occurrences}")
                if secret.hmsl_url:
                    ui.display_info(f"       First seen: {secret.hmsl_url}")
                ui.display_info(f"       Value: {secret.gathered_secret.value}")
                i += 1

    # ─── Non-leaked Secrets Section ───
    if non_leaked_secrets:
        ui.display_info("")
        ui.display_info("── Not Leaked ──")

        # Sort secrets by group using same priority as summary (generic types last)
        sorted_groups = sorted(
            counts.keys(),
            key=lambda d: (_get_group_priority(d), -counts[d]["count"]),
        )
        group_order = {group: idx for idx, group in enumerate(sorted_groups)}

        sorted_secrets = sorted(
            non_leaked_secrets,
            key=lambda s: group_order.get(_get_group_name(s), 999),
        )

        current_group = None
        i = 1
        for secret in sorted_secrets:
            metadata = secret.gathered_secret.metadata
            group = _get_group_name(secret)

            # Add section header when group changes
            if group != current_group:
                current_group = group
                ui.display_info("")
                ui.display_info(f"  [{group}]")

            # Get source type label
            source_label = SOURCE_LABELS.get(
                metadata.source_type, metadata.source_type.name
            )

            # Build compact line: number, source type, validity, path[:name]
            # For deep scan secrets, don't show the redundant detector type (already in header)
            # For other secrets, show the field name (e.g., API_KEY, password)
            is_deep_scan = metadata.source_type == SourceType.DEEP_SCAN
            path_suffix = "" if is_deep_scan else f":{metadata.secret_name}"

            if secret.is_detected and secret.validity:
                validity = translate_validity(secret.validity).upper()
                line = f"  {i}. [{source_label}] [{validity}] {metadata.source_path}{path_suffix}"
            else:
                line = f"  {i}. [{source_label}] {metadata.source_path}{path_suffix}"

            if secret.known_secret:
                line += " (known)"

            ui.display_info(line)
            i += 1


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
            # Inventory-compatible fields (for GitGuardian inventory uploads)
            "gim": {
                "kind": {
                    "type": "string",
                    "raw": {
                        "hash": secret.gg_hash,
                        "length": secret.gg_length,
                    },
                },
                "sub_path": metadata.secret_name,
            },
        }
        # Include leaked status and details if HMSL was run
        if secret.hmsl_leaked is not None:
            secret_data["leaked"] = secret.hmsl_leaked
            if secret.hmsl_leaked:
                secret_data["leak_info"] = {
                    "occurrences": secret.hmsl_occurrences,
                    "url": secret.hmsl_url,
                    "value": secret.gathered_secret.value,
                }
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
# HMSL check-only output functions (for `machine check` command)
# --------------------------------------------------------------------------


def display_hmsl_check_results(
    secrets: List[GatheredSecret],
    leaked_info: Dict[str, LeakedSecretInfo],
    json_output: bool = False,
    verbose: bool = False,
    leaked_threshold: int = 100,
) -> None:
    """
    Display HMSL check results for machine scan.

    Args:
        secrets: Original gathered secrets
        leaked_info: Dict mapping key (name + path) to LeakedSecretInfo
        json_output: If True, output JSON
        verbose: If True, show per-secret details with leak info
        leaked_threshold: Hide leaked secrets with >= N occurrences (0 = show all)
    """
    if json_output:
        _display_json_hmsl_results(secrets, leaked_info)
    elif verbose:
        _display_verbose_hmsl_results(secrets, leaked_info, leaked_threshold)
    else:
        _display_text_hmsl_results(secrets, leaked_info)


def _display_text_hmsl_results(
    secrets: List[GatheredSecret],
    leaked_info: Dict[str, LeakedSecretInfo],
) -> None:
    """Display HMSL check summary."""
    total = len(secrets)
    leaked_count = _count_leaked_secrets(secrets, leaked_info)

    _display_hmsl_header(leaked_count, total)

    ui.display_info("")
    ui.display_info("Use -v, --verbose to see all checked secrets.")
    ui.display_info(
        "Use `ggshield machine analyze` for full analysis with GitGuardian API."
    )


def _display_verbose_hmsl_results(
    secrets: List[GatheredSecret],
    leaked_info: Dict[str, LeakedSecretInfo],
    leaked_threshold: int = 100,
) -> None:
    """Display verbose HMSL check results with per-secret details and priority grouping."""
    total = len(secrets)

    # Count by source type and deep scan detector type
    counts = _group_by_source(secrets)
    deep_scan_counts = _group_deep_scan_by_detector(secrets)

    # Group leaked secrets by priority
    high_priority, medium_priority, hidden = _group_leaked_by_priority(
        leaked_info, leaked_threshold
    )
    leaked_count = len(high_priority) + len(medium_priority)
    hidden_count = len(hidden)
    total_leaked = leaked_count + hidden_count

    _display_hmsl_header(total_leaked, total)

    # Summary section
    if counts or deep_scan_counts:
        ui.display_info("")
        ui.display_info("── Summary ──")

        # Show deep scan secrets grouped by detector type first (generic types last)
        if deep_scan_counts:
            for detector, count in sorted(
                deep_scan_counts.items(),
                key=lambda x: (_get_group_priority(x[0]), -x[1]),
            ):
                ui.display_info(f"  {detector}: {count}")

        # Then show other source types
        _display_source_summary(counts)

    # Show hidden count in summary if any
    if hidden_count > 0:
        ui.display_info(
            f"\n  Hidden: {hidden_count} secrets (>={leaked_threshold} occurrences, likely false positives)"
        )

    # Build lookup from key to secret metadata for displaying match_name
    key_to_secret: Dict[str, GatheredSecret] = {}
    for s in secrets:
        key = f"{s.metadata.secret_name} ({s.metadata.source_path})"
        key_to_secret[key] = s

    # ─── Leaked Secrets Section (by priority) ───
    if high_priority or medium_priority:
        ui.display_info("")
        ui.display_info("── Leaked Secrets ──")
        i = 1

        # High priority (< 10 occurrences)
        if high_priority:
            ui.display_info("")
            ui.display_info(
                f"  [HIGH PRIORITY - <{HIGH_PRIORITY_THRESHOLD} occurrences]"
            )
            for info in high_priority:
                secret = key_to_secret.get(info.key)
                match_name = secret.metadata.match_name if secret else None

                ui.display_info(f"  {i}. [LEAKED] {info.key}")
                if match_name:
                    ui.display_info(f"       Key: {match_name}")
                ui.display_info(f"       Occurrences: {info.count}")
                if info.url:
                    ui.display_info(f"       First seen: {info.url}")
                ui.display_info(f"       Value: {info.secret_value}")
                i += 1

        # Medium priority (10-99 occurrences)
        if medium_priority:
            ui.display_info("")
            ui.display_info(
                f"  [MEDIUM PRIORITY - {HIGH_PRIORITY_THRESHOLD}-{MEDIUM_PRIORITY_THRESHOLD - 1} occurrences]"
            )
            for info in medium_priority:
                secret = key_to_secret.get(info.key)
                match_name = secret.metadata.match_name if secret else None

                ui.display_info(f"  {i}. [LEAKED] {info.key}")
                if match_name:
                    ui.display_info(f"       Key: {match_name}")
                ui.display_info(f"       Occurrences: {info.count}")
                if info.url:
                    ui.display_info(f"       First seen: {info.url}")
                ui.display_info(f"       Value: {info.secret_value}")
                i += 1

    # ─── Non-leaked Secrets Section ───
    # Separate deep scan secrets from others
    deep_scan_secrets = [
        s for s in secrets if s.metadata.source_type == SourceType.DEEP_SCAN
    ]
    other_secrets = [
        s for s in secrets if s.metadata.source_type != SourceType.DEEP_SCAN
    ]

    # Filter to only non-leaked secrets
    non_leaked_deep = [
        s
        for s in deep_scan_secrets
        if f"{s.metadata.secret_name} ({s.metadata.source_path})" not in leaked_info
    ]
    non_leaked_other = [
        s
        for s in other_secrets
        if f"{s.metadata.secret_name} ({s.metadata.source_path})" not in leaked_info
    ]

    if non_leaked_deep or non_leaked_other:
        ui.display_info("")
        ui.display_info("── Not Leaked ──")

        # Sort deep scan secrets by detector type (generic types last)
        if deep_scan_counts:
            detector_order = {
                dt: idx
                for idx, dt in enumerate(
                    sorted(
                        deep_scan_counts.keys(),
                        key=lambda dt: (_get_group_priority(dt), -deep_scan_counts[dt]),
                    )
                )
            }
            sorted_deep_scan = sorted(
                non_leaked_deep,
                key=lambda s: detector_order.get(s.metadata.secret_name, 999),
            )
        else:
            sorted_deep_scan = non_leaked_deep

        # Sort other secrets by source type (same order as summary)
        if counts:
            source_order = {
                st: idx
                for idx, st in enumerate(
                    sorted(counts.keys(), key=lambda st: -counts[st])
                )
            }
            sorted_other = sorted(
                non_leaked_other,
                key=lambda s: source_order.get(s.metadata.source_type, 999),
            )
        else:
            sorted_other = non_leaked_other

        # Display deep scan secrets first, grouped by detector type
        current_detector = None
        i = 1
        for secret in sorted_deep_scan:
            metadata = secret.metadata
            detector = metadata.secret_name

            # Add section header when detector type changes
            if detector != current_detector:
                current_detector = detector
                ui.display_info("")
                ui.display_info(f"  [{detector}]")

            ui.display_info(f"  {i}. [OK] {metadata.source_path}")
            i += 1

        # Display other secrets grouped by source type
        current_source = None
        for secret in sorted_other:
            metadata = secret.metadata

            # Add section header when source type changes
            if metadata.source_type != current_source:
                current_source = metadata.source_type
                label = SOURCE_LABELS.get(current_source, current_source.name)
                ui.display_info("")
                ui.display_info(f"  [{label}]")

            ui.display_info(
                f"  {i}. [OK] {metadata.source_path}:{metadata.secret_name}"
            )
            i += 1

    ui.display_info("")
    ui.display_info(
        "Use `ggshield machine analyze` for full analysis with GitGuardian API."
    )


def _display_json_hmsl_results(
    secrets: List[GatheredSecret],
    leaked_info: Dict[str, LeakedSecretInfo],
) -> None:
    """Display HMSL check results as JSON."""
    secrets_data = []
    for secret in secrets:
        metadata = secret.metadata
        key = f"{metadata.secret_name} ({metadata.source_path})"
        info = leaked_info.get(key)

        secret_entry: Dict[str, Any] = {
            "source": {
                "type": metadata.source_type.name,
                "path": metadata.source_path,
                "name": metadata.secret_name,
            },
            "leaked": info is not None,
        }

        # Include detailed leak info if leaked
        if info:
            secret_entry["leak_info"] = {
                "occurrences": info.count,
                "url": info.url,
                "value": info.secret_value,
            }

        secrets_data.append(secret_entry)

    leaked_count = sum(1 for s in secrets_data if s["leaked"])
    data = {
        "secrets_checked": len(secrets),
        "leaked_count": leaked_count,
        "secrets": secrets_data,
    }
    click.echo(json.dumps(data, indent=2))
