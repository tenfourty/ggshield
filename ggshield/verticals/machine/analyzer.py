"""
Secret analyzer for machine scan - uses GitGuardian API to identify secret types.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from pygitguardian import GGClient
from pygitguardian.models import Detail, MultiScanResult, ScanResult, TokenScope

from ggshield.core.client import check_client_api_key
from ggshield.core.errors import QuotaLimitReachedError, handle_api_error
from ggshield.utils.itertools import batched
from ggshield.verticals.machine.sources import GatheredSecret


logger = logging.getLogger(__name__)


# GitGuardian API path length limit
_API_PATH_MAX_LENGTH = 256

# Default batch size if client preferences unavailable
_DEFAULT_BATCH_SIZE = 20


@dataclass
class AnalyzedSecret:
    """A gathered secret with analysis results from GitGuardian API."""

    gathered_secret: GatheredSecret

    # Analysis results from API
    detector_name: Optional[str] = None  # e.g., "aws_access_key"
    detector_display_name: Optional[str] = None  # e.g., "AWS Keys"
    validity: Optional[str] = None  # "valid", "invalid", "unknown", "no_checker"
    known_secret: bool = False
    incident_url: Optional[str] = None

    # For combined --analyze --check results
    hmsl_leaked: Optional[bool] = None

    @property
    def is_detected(self) -> bool:
        """Return True if the API identified this as a known secret type."""
        return self.detector_name is not None

    @property
    def gim_hash(self) -> str:
        """Scrypt hash for GIM inventory (reuses HMSL hash function)."""
        from ggshield.verticals.hmsl.crypto import hash_string

        return hash_string(self.gathered_secret.value)

    @property
    def gim_length(self) -> int:
        """Byte length for GIM inventory."""
        return len(self.gathered_secret.value.encode("utf-8"))


@dataclass
class AnalysisResult:
    """Result from analyzing gathered secrets."""

    analyzed_secrets: List[AnalyzedSecret] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    unanalyzed_count: int = 0
    fetched_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def detected_count(self) -> int:
        """Count of secrets that were identified as known secret types."""
        return sum(1 for s in self.analyzed_secrets if s.is_detected)

    @property
    def known_secrets_count(self) -> int:
        """Count of secrets already tracked in GitGuardian dashboard."""
        return sum(1 for s in self.analyzed_secrets if s.known_secret)

    def get_counts_by_detector(self) -> Dict[str, Dict[str, int]]:
        """
        Group secrets by detector type and count validity statuses.

        Returns dict like:
        {
            "AWS Keys": {"count": 3, "valid": 2, "invalid": 1, "unknown": 0},
            "GitHub Token": {"count": 2, "valid": 2, "invalid": 0, "unknown": 0},
        }
        """
        counts: Dict[str, Dict[str, int]] = {}

        for secret in self.analyzed_secrets:
            if not secret.is_detected:
                detector = "Unknown"
            else:
                detector = secret.detector_display_name or secret.detector_name or "Unknown"

            if detector not in counts:
                counts[detector] = {"count": 0, "valid": 0, "invalid": 0, "unknown": 0}

            counts[detector]["count"] += 1

            validity = secret.validity or "unknown"
            if validity in ("valid", "invalid"):
                counts[detector][validity] += 1
            else:
                counts[detector]["unknown"] += 1

        return counts


class MachineSecretAnalyzer:
    """Analyzes gathered secrets using the GitGuardian scanning API."""

    def __init__(
        self,
        client: GGClient,
        headers: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize the analyzer.

        Args:
            client: GitGuardian API client
            headers: Optional HTTP headers for API requests
        """
        self.client = client
        self.headers = headers or {}

    def analyze(self, secrets: List[GatheredSecret]) -> AnalysisResult:
        """
        Send secrets to the scanning API for analysis.

        Returns AnalysisResult with detector info, validity, and known_secret status.
        Does NOT create incidents in the dashboard.
        """
        if not secrets:
            return AnalysisResult()

        # Check API key has required scopes
        check_client_api_key(self.client, {TokenScope.SCAN})

        result = AnalysisResult()

        # Get batch size from client preferences
        batch_size = int(
            getattr(
                self.client.secret_scan_preferences,
                "maximum_documents_per_scan",
                _DEFAULT_BATCH_SIZE,
            )
        )

        # Process secrets in batches
        all_analyzed: List[AnalyzedSecret] = []

        for batch in batched(secrets, batch_size):
            batch_list = list(batch)
            documents = self._create_documents(batch_list)

            try:
                scan_result = self.client.multi_content_scan(
                    documents,
                    self.headers,
                    all_secrets=True,
                )

                if isinstance(scan_result, Detail):
                    handle_api_error(scan_result)
                    result.errors.append(f"API error: {scan_result.detail}")
                    result.unanalyzed_count += len(batch_list)
                    continue

                # Merge this batch's results
                all_analyzed.extend(self._merge_results(batch_list, scan_result))

            except QuotaLimitReachedError:
                result.errors.append("API quota limit reached")
                result.unanalyzed_count += len(batch_list)
                raise
            except Exception as e:
                logger.exception("Error during secret analysis")
                result.errors.append(f"Analysis error: {e}")
                result.unanalyzed_count += len(batch_list)

        result.analyzed_secrets = all_analyzed
        return result

    def _create_documents(
        self, secrets: List[GatheredSecret]
    ) -> List[Dict[str, str]]:
        """
        Convert gathered secrets to document format for API.

        Each document contains:
        - document: The secret value to analyze
        - filename: Source path for context (truncated to API limit)
        """
        documents = []
        for secret in secrets:
            # Use source path and name for context
            filename = f"{secret.metadata.source_path}:{secret.metadata.secret_name}"
            documents.append({
                "document": secret.value,
                "filename": filename[-_API_PATH_MAX_LENGTH:],
            })
        return documents

    def _merge_results(
        self,
        secrets: List[GatheredSecret],
        scan_result: MultiScanResult,
    ) -> List[AnalyzedSecret]:
        """
        Merge API scan results with original gathered secrets.

        The API returns results in the same order as the input documents.
        """
        analyzed = []

        for secret, result in zip(secrets, scan_result.scan_results):
            analyzed_secret = self._process_scan_result(secret, result)
            analyzed.append(analyzed_secret)

        return analyzed

    def _process_scan_result(
        self,
        secret: GatheredSecret,
        result: ScanResult,
    ) -> AnalyzedSecret:
        """Process a single scan result and create an AnalyzedSecret."""
        if result.policy_breaks:
            # Take the first policy break (primary detection)
            policy_break = result.policy_breaks[0]
            return AnalyzedSecret(
                gathered_secret=secret,
                detector_name=policy_break.detector_name,
                detector_display_name=policy_break.break_type,
                validity=policy_break.validity,
                known_secret=policy_break.known_secret,
                incident_url=policy_break.incident_url,
            )
        else:
            # No detection - include but mark as undetected
            return AnalyzedSecret(
                gathered_secret=secret,
                detector_name=None,
                detector_display_name=None,
                validity=None,
                known_secret=False,
                incident_url=None,
            )
