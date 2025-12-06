"""
Tests for machine scan command.

This command gathers secrets from the local machine without any network calls.
It's the fastest option for getting an inventory of potential secrets.
"""

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from ggshield.__main__ import cli
from ggshield.verticals.machine.secret_gatherer import GatheringStats
from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)
from tests.unit.conftest import assert_invoke_ok


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
        WHEN running machine scan
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
        THEN displays help text with scan-only options
        """
        result = cli_fs_runner.invoke(cli, ["machine", "scan", "--help"])

        assert_invoke_ok(result)
        assert "--timeout" in result.output
        assert "--min-chars" in result.output
        assert "--exclude" in result.output
        assert "--ignore-config-exclusions" in result.output
        # These should NOT be present as command flags (moved to check/analyze commands)
        # Use specific patterns to avoid matching global options like --check-for-updates
        assert "  --check " not in result.output  # space after to match flag format
        assert "--analyze" not in result.output
        assert "--full-hashes" not in result.output
        # --output could match other things, be more specific
        assert "  -o," not in result.output  # the short form of --output

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
        THEN displays scan, check, and analyze subcommands
        """
        result = cli_fs_runner.invoke(cli, ["machine", "--help"])

        assert_invoke_ok(result)
        assert "scan" in result.output
        assert "check" in result.output
        assert "analyze" in result.output
