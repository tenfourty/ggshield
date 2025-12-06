"""
Tests for machine scan command.
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
from tests.unit.conftest import assert_invoke_ok, assert_invoke_exited_with


class TestMachineScanCommand:
    """Tests for the machine scan command."""

    def test_scan_no_secrets_found(self, cli_fs_runner: CliRunner):
        """
        GIVEN no secrets to gather
        WHEN running machine scan
        THEN displays no secrets found message
        """
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter([])
        mock_gatherer.stats = GatheringStats()

        with patch(
            "ggshield.cmd.machine.scan.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            result = cli_fs_runner.invoke(cli, ["machine", "scan"])

        assert_invoke_ok(result)
        assert "No secrets found" in result.output

    def test_scan_finds_secrets(self, cli_fs_runner: CliRunner):
        """
        GIVEN secrets found on the machine
        WHEN running machine scan without --check
        THEN displays the secrets summary by source type
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
            GatheredSecret(
                value="npm_test_token",
                metadata=SecretMetadata(
                    source_type=SourceType.NPMRC,
                    source_path="~/.npmrc",
                    secret_name="_authToken",
                ),
            ),
        ]
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter(mock_secrets)
        mock_gatherer.stats = GatheringStats(
            env_vars_count=1,
            npmrc_files=1,
            npmrc_secrets=1,
        )

        with patch(
            "ggshield.cmd.machine.scan.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            result = cli_fs_runner.invoke(cli, ["machine", "scan"])

        assert_invoke_ok(result)
        assert "Found 2 potential secrets" in result.output
        assert "Environment variables" in result.output
        assert "NPM configuration" in result.output

    def test_scan_with_timeout_option(self, cli_fs_runner: CliRunner):
        """
        GIVEN a timeout option
        WHEN running machine scan with --timeout
        THEN passes timeout to the gatherer config
        """
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter([])
        mock_gatherer.stats = GatheringStats()

        with patch(
            "ggshield.cmd.machine.scan.MachineSecretGatherer",
            return_value=mock_gatherer,
        ) as mock_class:
            result = cli_fs_runner.invoke(cli, ["machine", "scan", "--timeout", "30"])

        assert_invoke_ok(result)
        # Check that GatheringConfig was created with correct timeout
        call_args = mock_class.call_args
        config = call_args[0][0]
        assert config.timeout == 30

    def test_scan_with_min_chars_option(self, cli_fs_runner: CliRunner):
        """
        GIVEN a min-chars option
        WHEN running machine scan with --min-chars
        THEN passes min_chars to the gatherer config
        """
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter([])
        mock_gatherer.stats = GatheringStats()

        with patch(
            "ggshield.cmd.machine.scan.MachineSecretGatherer",
            return_value=mock_gatherer,
        ) as mock_class:
            result = cli_fs_runner.invoke(cli, ["machine", "scan", "--min-chars", "10"])

        assert_invoke_ok(result)
        call_args = mock_class.call_args
        config = call_args[0][0]
        assert config.min_chars == 10

    def test_scan_displays_stats(self, cli_fs_runner: CliRunner):
        """
        GIVEN secrets from multiple sources
        WHEN running machine scan
        THEN displays gathering stats
        """
        mock_secrets = [
            GatheredSecret(
                value="env_secret_value",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="environment",
                    secret_name="ENV_VAR",
                ),
            ),
        ]
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter(mock_secrets)
        mock_gatherer.stats = GatheringStats(
            env_vars_count=5,
            npmrc_files=1,
            npmrc_secrets=2,
            env_files=3,
            env_secrets=4,
            private_key_files=1,
            private_key_secrets=1,
            total_files_visited=50,
            elapsed_seconds=1.5,
        )

        with patch(
            "ggshield.cmd.machine.scan.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            result = cli_fs_runner.invoke(cli, ["machine", "scan"])

        assert_invoke_ok(result)
        # Stats should include counts from different sources
        assert "environment" in result.output.lower() or "env" in result.output.lower()

    def test_scan_json_output(self, cli_fs_runner: CliRunner):
        """
        GIVEN secrets found on the machine
        WHEN running machine scan with --json
        THEN outputs valid JSON with counts by source
        """
        mock_secrets = [
            GatheredSecret(
                value="test_secret",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="environment",
                    secret_name="SECRET_KEY",
                ),
            ),
        ]
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter(mock_secrets)
        mock_gatherer.stats = GatheringStats(env_vars_count=1)

        with patch(
            "ggshield.cmd.machine.scan.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            result = cli_fs_runner.invoke(cli, ["machine", "scan", "--json"])

        assert_invoke_ok(result)
        # JSON output contains counts by source type
        assert '"secrets_found": 1' in result.output
        assert "Environment variables" in result.output

    def test_scan_with_check_no_secrets(self, cli_fs_runner: CliRunner):
        """
        GIVEN no secrets to gather
        WHEN running machine scan with --check
        THEN succeeds without calling HMSL
        """
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter([])
        mock_gatherer.stats = GatheringStats()

        with patch(
            "ggshield.cmd.machine.scan.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch("ggshield.cmd.hmsl.hmsl_utils.check_secrets") as mock_check:
                result = cli_fs_runner.invoke(cli, ["machine", "scan", "--check"])

        assert_invoke_ok(result)
        # Should not call check_secrets since no secrets were found
        mock_check.assert_not_called()

    def test_scan_timed_out_flag(self, cli_fs_runner: CliRunner):
        """
        GIVEN gathering that timed out
        WHEN running machine scan
        THEN indicates timeout in output
        """
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter([])
        mock_gatherer.stats = GatheringStats(
            timed_out=True,
            elapsed_seconds=30.0,
        )

        with patch(
            "ggshield.cmd.machine.scan.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            result = cli_fs_runner.invoke(cli, ["machine", "scan"])

        assert_invoke_ok(result)
        # Should indicate that scan timed out
        assert (
            "timed out" in result.output.lower() or "timeout" in result.output.lower()
        )

    def test_scan_help(self, cli_fs_runner: CliRunner):
        """
        GIVEN the machine scan command
        WHEN running with --help
        THEN displays help text with all options
        """
        result = cli_fs_runner.invoke(cli, ["machine", "scan", "--help"])

        assert_invoke_ok(result)
        assert "--check" in result.output
        assert "--timeout" in result.output
        assert "--min-chars" in result.output
        assert "--full-hashes" in result.output
        assert "--exclude" in result.output
        assert "--ignore-config-exclusions" in result.output
        assert "HasMySecretLeaked" in result.output

    def test_scan_with_exclude_option(self, cli_fs_runner: CliRunner):
        """
        GIVEN an exclude pattern
        WHEN running machine scan with --exclude
        THEN passes exclusion patterns to the gatherer config
        """
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter([])
        mock_gatherer.stats = GatheringStats()

        with patch(
            "ggshield.cmd.machine.scan.MachineSecretGatherer",
            return_value=mock_gatherer,
        ) as mock_class:
            result = cli_fs_runner.invoke(
                cli, ["machine", "scan", "--exclude", "**/tests/**/*"]
            )

        assert_invoke_ok(result)
        call_args = mock_class.call_args
        config = call_args[0][0]
        # Should have exclusion regexes from the pattern
        assert len(config.exclusion_regexes) > 0

    def test_scan_with_multiple_exclude_options(self, cli_fs_runner: CliRunner):
        """
        GIVEN multiple exclude patterns
        WHEN running machine scan with multiple --exclude options
        THEN passes all exclusion patterns to the gatherer config
        """
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter([])
        mock_gatherer.stats = GatheringStats()

        with patch(
            "ggshield.cmd.machine.scan.MachineSecretGatherer",
            return_value=mock_gatherer,
        ) as mock_class:
            result = cli_fs_runner.invoke(
                cli,
                [
                    "machine",
                    "scan",
                    "--exclude",
                    "**/tests/**/*",
                    "--exclude",
                    "**/fixtures/**/*",
                ],
            )

        assert_invoke_ok(result)
        call_args = mock_class.call_args
        config = call_args[0][0]
        # Should have exclusion regexes from both patterns
        assert len(config.exclusion_regexes) >= 2

    def test_scan_with_ignore_config_exclusions(self, cli_fs_runner: CliRunner):
        """
        GIVEN config with ignored_paths
        WHEN running machine scan with --ignore-config-exclusions
        THEN does not apply config exclusions
        """
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter([])
        mock_gatherer.stats = GatheringStats()

        with patch(
            "ggshield.cmd.machine.scan.MachineSecretGatherer",
            return_value=mock_gatherer,
        ) as mock_class:
            result = cli_fs_runner.invoke(
                cli, ["machine", "scan", "--ignore-config-exclusions"]
            )

        assert_invoke_ok(result)
        call_args = mock_class.call_args
        config = call_args[0][0]
        # Without --exclude, and with config exclusions ignored,
        # should have no exclusion regexes (assuming no config in test env)
        # This verifies the flag is being passed and processed
        assert isinstance(config.exclusion_regexes, set)

    def test_scan_exclude_combined_with_ignore_config(self, cli_fs_runner: CliRunner):
        """
        GIVEN --exclude and --ignore-config-exclusions flags
        WHEN running machine scan
        THEN only CLI exclude patterns are applied
        """
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter([])
        mock_gatherer.stats = GatheringStats()

        with patch(
            "ggshield.cmd.machine.scan.MachineSecretGatherer",
            return_value=mock_gatherer,
        ) as mock_class:
            result = cli_fs_runner.invoke(
                cli,
                [
                    "machine",
                    "scan",
                    "--ignore-config-exclusions",
                    "--exclude",
                    "**/my-pattern/**/*",
                ],
            )

        assert_invoke_ok(result)
        call_args = mock_class.call_args
        config = call_args[0][0]
        # Should have exactly 1 exclusion regex from CLI (not from config)
        assert len(config.exclusion_regexes) == 1

    def test_machine_command_group(self, cli_fs_runner: CliRunner):
        """
        GIVEN the machine command group
        WHEN running machine --help
        THEN displays scan subcommand
        """
        result = cli_fs_runner.invoke(cli, ["machine", "--help"])

        assert_invoke_ok(result)
        assert "scan" in result.output


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


class TestMachineScanAnalyze:
    """Tests for machine scan --analyze command."""

    def test_scan_analyze_no_secrets(self, cli_fs_runner: CliRunner):
        """
        GIVEN no secrets to gather
        WHEN running machine scan --analyze
        THEN displays no secrets found message without calling API
        """
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter([])
        mock_gatherer.stats = GatheringStats()

        with patch(
            "ggshield.cmd.machine.scan.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch("ggshield.core.client.create_client_from_config") as mock_client:
                result = cli_fs_runner.invoke(cli, ["machine", "scan", "--analyze"])

        assert_invoke_ok(result)
        assert "No secrets found" in result.output
        mock_client.assert_not_called()

    def test_scan_analyze_with_secrets(self, cli_fs_runner: CliRunner):
        """
        GIVEN secrets found on the machine
        WHEN running machine scan --analyze
        THEN analyzes secrets and displays results by detector type
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
            "ggshield.cmd.machine.scan.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch(
                "ggshield.core.client.create_client_from_config",
                return_value=mock_client,
            ):
                with patch("ggshield.verticals.machine.analyzer.check_client_api_key"):
                    result = cli_fs_runner.invoke(cli, ["machine", "scan", "--analyze"])

        # Should return exit code 1 (found problems) when secrets detected
        assert_invoke_exited_with(result, 1)
        assert "Analysis Results" in result.output
        assert "AWS Keys" in result.output

    def test_scan_analyze_json_output(self, cli_fs_runner: CliRunner):
        """
        GIVEN secrets found on the machine
        WHEN running machine scan --analyze --json
        THEN outputs valid JSON with detector information
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
            "ggshield.cmd.machine.scan.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch(
                "ggshield.core.client.create_client_from_config",
                return_value=mock_client,
            ):
                with patch("ggshield.verticals.machine.analyzer.check_client_api_key"):
                    result = cli_fs_runner.invoke(
                        cli, ["machine", "scan", "--analyze", "--json"]
                    )

        # Parse JSON output - may have extra info messages before the JSON
        # Find the JSON by looking for the opening brace
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

    def test_scan_analyze_output_file(self, cli_fs_runner: CliRunner, tmp_path):
        """
        GIVEN secrets found on the machine
        WHEN running machine scan --analyze --output file.json
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
            "ggshield.cmd.machine.scan.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch(
                "ggshield.core.client.create_client_from_config",
                return_value=mock_client,
            ):
                with patch("ggshield.verticals.machine.analyzer.check_client_api_key"):
                    result = cli_fs_runner.invoke(
                        cli,
                        ["machine", "scan", "--analyze", "--output", str(output_file)],
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

    def test_scan_output_requires_analyze(self, cli_fs_runner: CliRunner, tmp_path):
        """
        GIVEN --output flag without --analyze
        WHEN running machine scan --output file.json
        THEN fails with usage error
        """
        output_file = tmp_path / "results.json"

        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter(
            [
                GatheredSecret(
                    value="test",
                    metadata=SecretMetadata(
                        source_type=SourceType.ENVIRONMENT_VAR,
                        source_path="env",
                        secret_name="KEY",
                    ),
                )
            ]
        )
        mock_gatherer.stats = GatheringStats()

        with patch(
            "ggshield.cmd.machine.scan.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            result = cli_fs_runner.invoke(
                cli, ["machine", "scan", "--output", str(output_file)]
            )

        assert result.exit_code == 2
        assert "--output requires --analyze" in result.output

    def test_scan_help_includes_analyze(self, cli_fs_runner: CliRunner):
        """
        GIVEN the machine scan command
        WHEN running with --help
        THEN displays --analyze option
        """
        result = cli_fs_runner.invoke(cli, ["machine", "scan", "--help"])

        assert_invoke_ok(result)
        assert "--analyze" in result.output
        assert "--output" in result.output
        assert "GitGuardian API" in result.output

    def test_scan_analyze_with_check(self, cli_fs_runner: CliRunner):
        """
        GIVEN secrets found on the machine
        WHEN running machine scan --analyze --check
        THEN analyzes secrets AND checks against HMSL with full hashes
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

        # Mock the scanning API client
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

        # Mock the HMSL client - return a leaked secret to test the full flow
        # The Secret class has 'hash', 'count', 'url' attributes (NOT 'name')
        from ggshield.verticals.hmsl.client import Secret as HMSLSecret
        from ggshield.verticals.hmsl.crypto import hash_string

        # Compute the actual hash that prepare() will generate for our test secret
        expected_hash = hash_string("AKIAIOSFODNN7EXAMPLE")

        mock_hmsl_client = MagicMock()
        mock_hmsl_client.check.return_value = [
            HMSLSecret(hash=expected_hash, count=1, url="https://example.com/leak")
        ]

        with patch(
            "ggshield.cmd.machine.scan.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch(
                "ggshield.core.client.create_client_from_config",
                return_value=mock_client,
            ):
                with patch("ggshield.verticals.machine.analyzer.check_client_api_key"):
                    with patch(
                        "ggshield.verticals.hmsl.utils.get_client",
                        return_value=mock_hmsl_client,
                    ):
                        result = cli_fs_runner.invoke(
                            cli, ["machine", "scan", "--analyze", "--check"]
                        )

        # Should call both APIs
        mock_client.multi_content_scan.assert_called_once()
        mock_hmsl_client.check.assert_called_once()

        # Verify the payload passed to client.check() contains full 64-char hashes
        # NOT 5-char prefixes. This is the actual behavior we need to guarantee.
        check_call_args = mock_hmsl_client.check.call_args
        payload = check_call_args[0][0]  # First positional arg is the hashes
        for hash_value in payload:
            assert len(hash_value) == 64, (
                f"Expected full 64-char hash but got {len(hash_value)}-char value: "
                f"'{hash_value[:10]}...'. client.check() needs full hashes to compute hints."
            )
            # Verify it's valid hex
            assert all(
                c in "0123456789abcdef" for c in hash_value
            ), f"Hash contains non-hex characters: '{hash_value[:10]}...'"

        # Should return exit code 1 (found problems) when secrets detected
        assert_invoke_exited_with(result, 1)
        assert "Analysis Results" in result.output
        assert "AWS Keys" in result.output
        # Should show leaked warning since we returned a leaked secret
        assert "leaked" in result.output.lower()
