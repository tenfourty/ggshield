"""
Tests for machine analyze command.

This command gathers secrets, checks them against HMSL for leaks,
and analyzes them using the GitGuardian API for detector type and validity.
"""

import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner
from pygitguardian.models import Match, MultiScanResult, PolicyBreak, ScanResult

from ggshield.__main__ import cli
from ggshield.verticals.machine.secret_gatherer import GatheringStats
from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)
from tests.unit.conftest import assert_invoke_exited_with, assert_invoke_ok


def _make_policy_break(
    detector_name: str = "generic_api_key",
    break_type: str = "Generic API Key",
    validity: str = "valid",
    known_secret: bool = False,
) -> PolicyBreak:
    """Create a test PolicyBreak."""
    return PolicyBreak(
        break_type=break_type,
        policy="Secrets detection",
        detector_name=detector_name,
        detector_group_name=break_type,
        validity=validity,
        known_secret=known_secret,
        incident_url=None,
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


def _make_scan_result(policy_breaks: list = None) -> ScanResult:
    """Create a test ScanResult."""
    if policy_breaks is None:
        policy_breaks = []
    return ScanResult(
        policy_break_count=len(policy_breaks),
        policy_breaks=policy_breaks,
        policies=["Secrets detection"],
    )


class TestMachineAnalyzeCommand:
    """Tests for the machine analyze command."""

    def test_analyze_no_secrets_found(self, cli_fs_runner: CliRunner):
        """
        GIVEN no secrets to gather
        WHEN running machine analyze
        THEN displays no secrets found message without calling APIs
        """
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter([])
        mock_gatherer.stats = GatheringStats()

        with patch(
            "ggshield.cmd.machine.analyze.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch("ggshield.core.client.create_client_from_config") as mock_client:
                result = cli_fs_runner.invoke(cli, ["machine", "analyze"])

        assert_invoke_ok(result)
        assert "No secrets found" in result.output
        mock_client.assert_not_called()

    def test_analyze_with_secrets(self, cli_fs_runner: CliRunner):
        """
        GIVEN secrets found on the machine
        WHEN running machine analyze
        THEN analyzes secrets with GitGuardian API and displays results
        """
        mock_secrets = [
            GatheredSecret(
                value="AKIAIOSFODNN7EXAMPLE",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="environment",
                    secret_name="AWS_ACCESS_KEY_ID",
                ),
            ),
        ]
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter(mock_secrets)
        mock_gatherer.stats = GatheringStats(env_vars_count=1)

        mock_client = MagicMock()
        mock_client.multi_content_scan.return_value = MultiScanResult(
            scan_results=[
                _make_scan_result(
                    [
                        _make_policy_break(
                            detector_name="aws_access_key",
                            break_type="AWS Keys",
                            validity="valid",
                        )
                    ]
                )
            ]
        )

        with patch(
            "ggshield.cmd.machine.analyze.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch(
                "ggshield.core.client.create_client_from_config",
                return_value=mock_client,
            ):
                with patch("ggshield.verticals.machine.analyzer.check_client_api_key"):
                    with patch("ggshield.cmd.machine.analyze.check_leaks"):
                        result = cli_fs_runner.invoke(cli, ["machine", "analyze"])

        # Should return exit code 1 (found problems) when secrets detected
        assert_invoke_exited_with(result, 1)
        assert (
            "Analysis Results" in result.output or "analyzed" in result.output.lower()
        )
        assert "AWS Keys" in result.output or "aws" in result.output.lower()

    def test_analyze_runs_hmsl_check(self, cli_fs_runner: CliRunner):
        """
        GIVEN secrets found on the machine
        WHEN running machine analyze
        THEN checks secrets against HMSL before analyzing
        """
        mock_secrets = [
            GatheredSecret(
                value="test_secret_value",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="environment",
                    secret_name="API_KEY",
                ),
            ),
        ]
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter(mock_secrets)
        mock_gatherer.stats = GatheringStats(env_vars_count=1)

        mock_client = MagicMock()
        mock_client.multi_content_scan.return_value = MultiScanResult(
            scan_results=[_make_scan_result([_make_policy_break()])]
        )

        with patch(
            "ggshield.cmd.machine.analyze.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch(
                "ggshield.core.client.create_client_from_config",
                return_value=mock_client,
            ):
                with patch("ggshield.verticals.machine.analyzer.check_client_api_key"):
                    with patch("ggshield.cmd.machine.analyze.check_leaks") as mock_hmsl:
                        cli_fs_runner.invoke(cli, ["machine", "analyze"])

        # HMSL check should have been called
        mock_hmsl.assert_called_once()

    def test_analyze_json_output(self, cli_fs_runner: CliRunner):
        """
        GIVEN secrets found on the machine
        WHEN running machine analyze --json
        THEN outputs valid JSON with detector information and GIM fields
        """
        mock_secrets = [
            GatheredSecret(
                value="test_secret",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="environment",
                    secret_name="API_KEY",
                ),
            ),
        ]
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter(mock_secrets)
        mock_gatherer.stats = GatheringStats(env_vars_count=1)

        mock_client = MagicMock()
        mock_client.multi_content_scan.return_value = MultiScanResult(
            scan_results=[
                _make_scan_result(
                    [
                        _make_policy_break(
                            detector_name="generic_api_key",
                            break_type="Generic API Key",
                        )
                    ]
                )
            ]
        )

        with patch(
            "ggshield.cmd.machine.analyze.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch(
                "ggshield.core.client.create_client_from_config",
                return_value=mock_client,
            ):
                with patch("ggshield.verticals.machine.analyzer.check_client_api_key"):
                    with patch("ggshield.cmd.machine.analyze.check_leaks"):
                        result = cli_fs_runner.invoke(
                            cli, ["machine", "analyze", "--json"]
                        )

        # Parse JSON output - find the JSON by looking for the opening brace
        output_lines = result.output.strip().split("\n")
        json_start = next(
            (i for i, line in enumerate(output_lines) if line.strip().startswith("{")),
            0,
        )
        json_output = "\n".join(output_lines[json_start:])
        output_data = json.loads(json_output)

        assert "secrets_analyzed" in output_data
        assert output_data["secrets_analyzed"] == 1
        assert "by_detector" in output_data
        assert "Generic API Key" in output_data["by_detector"]

        # Verify GIM-compatible fields
        assert "fetched_at" in output_data
        assert "T" in output_data["fetched_at"]  # ISO format
        assert len(output_data["secrets"]) == 1
        secret = output_data["secrets"][0]
        assert "gim" in secret
        assert "kind" in secret["gim"]
        assert secret["gim"]["kind"]["type"] == "string"
        assert "raw" in secret["gim"]["kind"]
        assert "hash" in secret["gim"]["kind"]["raw"]
        assert len(secret["gim"]["kind"]["raw"]["hash"]) == 64  # scrypt hash
        assert "length" in secret["gim"]["kind"]["raw"]
        assert isinstance(secret["gim"]["kind"]["raw"]["length"], int)
        assert "sub_path" in secret["gim"]

    def test_analyze_output_file(self, cli_fs_runner: CliRunner, tmp_path):
        """
        GIVEN secrets found on the machine
        WHEN running machine analyze --output file.json
        THEN writes detailed JSON to file
        """
        output_file = tmp_path / "results.json"

        mock_secrets = [
            GatheredSecret(
                value="test_secret",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="environment",
                    secret_name="API_KEY",
                ),
            ),
        ]
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter(mock_secrets)
        mock_gatherer.stats = GatheringStats(env_vars_count=1)

        mock_client = MagicMock()
        mock_client.multi_content_scan.return_value = MultiScanResult(
            scan_results=[_make_scan_result([_make_policy_break()])]
        )

        with patch(
            "ggshield.cmd.machine.analyze.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch(
                "ggshield.core.client.create_client_from_config",
                return_value=mock_client,
            ):
                with patch("ggshield.verticals.machine.analyzer.check_client_api_key"):
                    with patch("ggshield.cmd.machine.analyze.check_leaks"):
                        result = cli_fs_runner.invoke(
                            cli,
                            ["machine", "analyze", "--output", str(output_file)],
                        )

        # File should be created with JSON content
        assert output_file.exists()
        file_content = json.loads(output_file.read_text())
        assert "secrets_analyzed" in file_content
        assert "secrets" in file_content
        assert f"Detailed results written to {output_file}" in result.output

        # Verify GIM-compatible fields in file output
        assert "fetched_at" in file_content
        assert len(file_content["secrets"]) == 1
        secret = file_content["secrets"][0]
        assert "gim" in secret
        assert secret["gim"]["kind"]["type"] == "string"
        assert len(secret["gim"]["kind"]["raw"]["hash"]) == 64

    def test_analyze_with_full_hashes_option(self, cli_fs_runner: CliRunner):
        """
        GIVEN secrets found and --full-hashes flag
        WHEN running machine analyze --full-hashes
        THEN passes full_hashes=True to HMSL check
        """
        mock_secrets = [
            GatheredSecret(
                value="test_secret_value",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="environment",
                    secret_name="API_KEY",
                ),
            ),
        ]
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter(mock_secrets)
        mock_gatherer.stats = GatheringStats(env_vars_count=1)

        mock_client = MagicMock()
        mock_client.multi_content_scan.return_value = MultiScanResult(
            scan_results=[_make_scan_result([_make_policy_break()])]
        )

        with patch(
            "ggshield.cmd.machine.analyze.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch(
                "ggshield.core.client.create_client_from_config",
                return_value=mock_client,
            ):
                with patch("ggshield.verticals.machine.analyzer.check_client_api_key"):
                    with patch("ggshield.cmd.machine.analyze.check_leaks") as mock_hmsl:
                        cli_fs_runner.invoke(
                            cli, ["machine", "analyze", "--full-hashes"]
                        )

        mock_hmsl.assert_called_once()
        # Verify full_hashes was passed
        call_kwargs = mock_hmsl.call_args[1]
        assert call_kwargs.get("full_hashes") is True

    def test_analyze_with_timeout_option(self, cli_fs_runner: CliRunner):
        """
        GIVEN a timeout option
        WHEN running machine analyze with --timeout
        THEN passes timeout to the gatherer config
        """
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter([])
        mock_gatherer.stats = GatheringStats()

        with patch(
            "ggshield.cmd.machine.analyze.MachineSecretGatherer",
            return_value=mock_gatherer,
        ) as mock_class:
            result = cli_fs_runner.invoke(
                cli, ["machine", "analyze", "--timeout", "30"]
            )

        assert_invoke_ok(result)
        call_args = mock_class.call_args
        config = call_args[0][0]
        assert config.timeout == 30

    def test_analyze_with_min_chars_option(self, cli_fs_runner: CliRunner):
        """
        GIVEN a min-chars option
        WHEN running machine analyze with --min-chars
        THEN passes min_chars to the gatherer config
        """
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter([])
        mock_gatherer.stats = GatheringStats()

        with patch(
            "ggshield.cmd.machine.analyze.MachineSecretGatherer",
            return_value=mock_gatherer,
        ) as mock_class:
            result = cli_fs_runner.invoke(
                cli, ["machine", "analyze", "--min-chars", "10"]
            )

        assert_invoke_ok(result)
        call_args = mock_class.call_args
        config = call_args[0][0]
        assert config.min_chars == 10

    def test_analyze_with_exclude_option(self, cli_fs_runner: CliRunner):
        """
        GIVEN an exclude pattern
        WHEN running machine analyze with --exclude
        THEN passes exclusion patterns to the gatherer config
        """
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter([])
        mock_gatherer.stats = GatheringStats()

        with patch(
            "ggshield.cmd.machine.analyze.MachineSecretGatherer",
            return_value=mock_gatherer,
        ) as mock_class:
            result = cli_fs_runner.invoke(
                cli, ["machine", "analyze", "--exclude", "**/tests/**/*"]
            )

        assert_invoke_ok(result)
        call_args = mock_class.call_args
        config = call_args[0][0]
        assert len(config.exclusion_regexes) > 0

    def test_analyze_help(self, cli_fs_runner: CliRunner):
        """
        GIVEN the machine analyze command
        WHEN running with --help
        THEN displays help text with all options
        """
        result = cli_fs_runner.invoke(cli, ["machine", "analyze", "--help"])

        assert_invoke_ok(result)
        assert "--timeout" in result.output
        assert "--min-chars" in result.output
        assert "--full-hashes" in result.output
        assert "--exclude" in result.output
        assert "--output" in result.output
        assert "GitGuardian" in result.output or "API" in result.output

    def test_machine_command_group_shows_analyze(self, cli_fs_runner: CliRunner):
        """
        GIVEN the machine command group
        WHEN running machine --help
        THEN displays analyze subcommand
        """
        result = cli_fs_runner.invoke(cli, ["machine", "--help"])

        assert_invoke_ok(result)
        assert "analyze" in result.output
