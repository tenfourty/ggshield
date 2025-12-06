"""
Unit tests for MachineSecretAnalyzer.
"""

from unittest.mock import MagicMock, patch

import pytest
from pygitguardian.models import Match, MultiScanResult, PolicyBreak, ScanResult

from ggshield.verticals.machine.analyzer import (
    AnalysisResult,
    AnalyzedSecret,
    MachineSecretAnalyzer,
)
from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)


def make_gathered_secret(
    value: str = "secret_value",
    source_type: SourceType = SourceType.ENVIRONMENT_VAR,
    source_path: str = "environment",
    secret_name: str = "API_KEY",
) -> GatheredSecret:
    """Create a test GatheredSecret."""
    return GatheredSecret(
        value=value,
        metadata=SecretMetadata(
            source_type=source_type,
            source_path=source_path,
            secret_name=secret_name,
        ),
    )


def make_policy_break(
    detector_name: str = "generic_api_key",
    break_type: str = "Generic API Key",
    validity: str = "valid",
    known_secret: bool = False,
    incident_url: str = None,
) -> PolicyBreak:
    """Create a test PolicyBreak."""
    return PolicyBreak(
        break_type=break_type,
        policy="Secrets detection",
        detector_name=detector_name,
        detector_group_name=break_type,
        validity=validity,
        known_secret=known_secret,
        incident_url=incident_url,
        is_excluded=False,
        is_vaulted=False,
        exclude_reason=None,
        diff_kind=None,
        matches=[
            Match(
                match="secret_value",
                match_type="api_key",
                index_start=0,
                index_end=12,
                line_start=0,
                line_end=0,
            )
        ],
    )


def make_scan_result(policy_breaks: list = None) -> ScanResult:
    """Create a test ScanResult."""
    if policy_breaks is None:
        policy_breaks = []
    return ScanResult(
        policy_break_count=len(policy_breaks),
        policy_breaks=policy_breaks,
        policies=["Secrets detection"],
    )


class TestAnalyzedSecret:
    """Tests for AnalyzedSecret dataclass."""

    def test_is_detected_true_when_detector_name_set(self):
        """Test is_detected returns True when detector_name is set."""
        secret = AnalyzedSecret(
            gathered_secret=make_gathered_secret(),
            detector_name="aws_access_key",
        )
        assert secret.is_detected is True

    def test_is_detected_false_when_detector_name_none(self):
        """Test is_detected returns False when detector_name is None."""
        secret = AnalyzedSecret(
            gathered_secret=make_gathered_secret(),
            detector_name=None,
        )
        assert secret.is_detected is False

    def test_gim_hash_returns_64_char_hex(self):
        """Test gim_hash returns a 64-character hex string (scrypt hash)."""
        secret = AnalyzedSecret(
            gathered_secret=make_gathered_secret(value="test_secret_value"),
            detector_name="aws_access_key",
        )
        gim_hash = secret.gim_hash
        assert len(gim_hash) == 64
        # Verify it's a valid hex string
        int(gim_hash, 16)

    def test_gim_length_returns_byte_length(self):
        """Test gim_length returns the UTF-8 byte length of the value."""
        # ASCII string - bytes == chars
        secret = AnalyzedSecret(
            gathered_secret=make_gathered_secret(value="hello"),
            detector_name="aws_access_key",
        )
        assert secret.gim_length == 5

        # Unicode string - bytes > chars
        secret_unicode = AnalyzedSecret(
            gathered_secret=make_gathered_secret(value="héllo"),
            detector_name="aws_access_key",
        )
        # 'é' is 2 bytes in UTF-8
        assert secret_unicode.gim_length == 6


class TestAnalysisResult:
    """Tests for AnalysisResult dataclass."""

    def test_fetched_at_is_set_automatically(self):
        """Test fetched_at is set to an ISO timestamp on creation."""
        result = AnalysisResult()
        # Should be a valid ISO timestamp
        assert result.fetched_at is not None
        # Should contain 'T' (ISO format separator)
        assert "T" in result.fetched_at
        # Should end with timezone info (UTC)
        assert "+" in result.fetched_at or "Z" in result.fetched_at

    def test_detected_count(self):
        """Test detected_count counts secrets with detector_name."""
        result = AnalysisResult(
            analyzed_secrets=[
                AnalyzedSecret(
                    gathered_secret=make_gathered_secret(),
                    detector_name="aws_access_key",
                ),
                AnalyzedSecret(
                    gathered_secret=make_gathered_secret(),
                    detector_name=None,
                ),
                AnalyzedSecret(
                    gathered_secret=make_gathered_secret(),
                    detector_name="github_token",
                ),
            ]
        )
        assert result.detected_count == 2

    def test_known_secrets_count(self):
        """Test known_secrets_count counts known secrets."""
        result = AnalysisResult(
            analyzed_secrets=[
                AnalyzedSecret(
                    gathered_secret=make_gathered_secret(),
                    known_secret=True,
                ),
                AnalyzedSecret(
                    gathered_secret=make_gathered_secret(),
                    known_secret=False,
                ),
                AnalyzedSecret(
                    gathered_secret=make_gathered_secret(),
                    known_secret=True,
                ),
            ]
        )
        assert result.known_secrets_count == 2

    def test_get_counts_by_detector(self):
        """Test grouping secrets by detector type."""
        result = AnalysisResult(
            analyzed_secrets=[
                AnalyzedSecret(
                    gathered_secret=make_gathered_secret(),
                    detector_name="aws_access_key",
                    detector_display_name="AWS Keys",
                    validity="valid",
                ),
                AnalyzedSecret(
                    gathered_secret=make_gathered_secret(),
                    detector_name="aws_access_key",
                    detector_display_name="AWS Keys",
                    validity="invalid",
                ),
                AnalyzedSecret(
                    gathered_secret=make_gathered_secret(),
                    detector_name="github_token",
                    detector_display_name="GitHub Token",
                    validity="valid",
                ),
            ]
        )
        counts = result.get_counts_by_detector()

        assert counts["AWS Keys"]["count"] == 2
        assert counts["AWS Keys"]["valid"] == 1
        assert counts["AWS Keys"]["invalid"] == 1
        assert counts["GitHub Token"]["count"] == 1
        assert counts["GitHub Token"]["valid"] == 1

    def test_get_counts_by_detector_unknown(self):
        """Test undetected secrets are grouped as Unknown."""
        result = AnalysisResult(
            analyzed_secrets=[
                AnalyzedSecret(
                    gathered_secret=make_gathered_secret(),
                    detector_name=None,
                ),
            ]
        )
        counts = result.get_counts_by_detector()

        assert "Unknown" in counts
        assert counts["Unknown"]["count"] == 1


class TestMachineSecretAnalyzer:
    """Tests for MachineSecretAnalyzer class."""

    def test_analyze_empty_secrets(self):
        """Test analyzing empty list returns empty result."""
        client = MagicMock()
        analyzer = MachineSecretAnalyzer(client)

        result = analyzer.analyze([])

        assert len(result.analyzed_secrets) == 0
        assert result.detected_count == 0
        client.multi_content_scan.assert_not_called()

    @patch("ggshield.verticals.machine.analyzer.check_client_api_key")
    def test_analyze_creates_documents(self, mock_check_api_key):
        """Test that gathered secrets are converted to documents correctly."""
        client = MagicMock()
        client.secret_scan_preferences.maximum_documents_per_scan = 20
        client.multi_content_scan.return_value = MultiScanResult(
            scan_results=[make_scan_result([make_policy_break()])]
        )

        analyzer = MachineSecretAnalyzer(client)
        secrets = [
            make_gathered_secret(
                value="AKIAIOSFODNN7EXAMPLE",
                source_path="/home/user/.env",
                secret_name="AWS_ACCESS_KEY_ID",
            )
        ]

        analyzer.analyze(secrets)

        # Verify document format
        call_args = client.multi_content_scan.call_args
        documents = call_args[0][0]
        assert len(documents) == 1
        assert documents[0]["document"] == "AKIAIOSFODNN7EXAMPLE"
        assert "/home/user/.env:AWS_ACCESS_KEY_ID" in documents[0]["filename"]

    @patch("ggshield.verticals.machine.analyzer.check_client_api_key")
    def test_analyze_merges_results(self, mock_check_api_key):
        """Test that API results are merged with gathered secrets."""
        client = MagicMock()
        client.secret_scan_preferences.maximum_documents_per_scan = 20
        client.multi_content_scan.return_value = MultiScanResult(
            scan_results=[
                make_scan_result([
                    make_policy_break(
                        detector_name="aws_access_key",
                        break_type="AWS Keys",
                        validity="valid",
                        known_secret=True,
                        incident_url="https://dashboard.gitguardian.com/incidents/123",
                    )
                ])
            ]
        )

        analyzer = MachineSecretAnalyzer(client)
        secrets = [make_gathered_secret(value="AKIAIOSFODNN7EXAMPLE")]

        result = analyzer.analyze(secrets)

        assert len(result.analyzed_secrets) == 1
        analyzed = result.analyzed_secrets[0]
        assert analyzed.detector_name == "aws_access_key"
        assert analyzed.detector_display_name == "AWS Keys"
        assert analyzed.validity == "valid"
        assert analyzed.known_secret is True
        assert analyzed.incident_url == "https://dashboard.gitguardian.com/incidents/123"
        assert analyzed.gathered_secret.value == "AKIAIOSFODNN7EXAMPLE"

    @patch("ggshield.verticals.machine.analyzer.check_client_api_key")
    def test_analyze_handles_no_detection(self, mock_check_api_key):
        """Test handling of secrets with no policy breaks."""
        client = MagicMock()
        client.secret_scan_preferences.maximum_documents_per_scan = 20
        client.multi_content_scan.return_value = MultiScanResult(
            scan_results=[make_scan_result([])]  # No policy breaks
        )

        analyzer = MachineSecretAnalyzer(client)
        secrets = [make_gathered_secret(value="some_random_value")]

        result = analyzer.analyze(secrets)

        assert len(result.analyzed_secrets) == 1
        analyzed = result.analyzed_secrets[0]
        assert analyzed.detector_name is None
        assert analyzed.is_detected is False

    @patch("ggshield.verticals.machine.analyzer.check_client_api_key")
    def test_analyze_multiple_secrets(self, mock_check_api_key):
        """Test analyzing multiple secrets."""
        client = MagicMock()
        # Set batch size to ensure all secrets are processed in one call
        client.secret_scan_preferences.maximum_documents_per_scan = 20
        client.multi_content_scan.return_value = MultiScanResult(
            scan_results=[
                make_scan_result([make_policy_break(
                    detector_name="aws_access_key",
                    break_type="AWS Keys",
                )]),
                make_scan_result([]),  # No detection
                make_scan_result([make_policy_break(
                    detector_name="github_token",
                    break_type="GitHub Token",
                )]),
            ]
        )

        analyzer = MachineSecretAnalyzer(client)
        secrets = [
            make_gathered_secret(value="AKIAIOSFODNN7EXAMPLE"),
            make_gathered_secret(value="random_value"),
            make_gathered_secret(value="ghp_xxxxxxxxxxxx"),
        ]

        result = analyzer.analyze(secrets)

        assert len(result.analyzed_secrets) == 3
        assert result.detected_count == 2
        assert result.analyzed_secrets[0].detector_name == "aws_access_key"
        assert result.analyzed_secrets[1].detector_name is None
        assert result.analyzed_secrets[2].detector_name == "github_token"

    @patch("ggshield.verticals.machine.analyzer.check_client_api_key")
    def test_analyze_passes_headers(self, mock_check_api_key):
        """Test that custom headers are passed to the API."""
        client = MagicMock()
        client.secret_scan_preferences.maximum_documents_per_scan = 20
        client.multi_content_scan.return_value = MultiScanResult(
            scan_results=[make_scan_result([])]
        )

        headers = {"X-Custom-Header": "test-value"}
        analyzer = MachineSecretAnalyzer(client, headers=headers)
        secrets = [make_gathered_secret()]

        analyzer.analyze(secrets)

        call_args = client.multi_content_scan.call_args
        assert call_args[0][1] == headers

    @patch("ggshield.verticals.machine.analyzer.check_client_api_key")
    def test_analyze_truncates_long_filenames(self, mock_check_api_key):
        """Test that long filenames are truncated to API limit."""
        client = MagicMock()
        client.secret_scan_preferences.maximum_documents_per_scan = 20
        client.multi_content_scan.return_value = MultiScanResult(
            scan_results=[make_scan_result([])]
        )

        analyzer = MachineSecretAnalyzer(client)
        long_path = "/very/long/" + "x" * 300 + "/path"
        secrets = [make_gathered_secret(source_path=long_path)]

        analyzer.analyze(secrets)

        call_args = client.multi_content_scan.call_args
        documents = call_args[0][0]
        # Filename should be truncated to 256 chars
        assert len(documents[0]["filename"]) <= 256
