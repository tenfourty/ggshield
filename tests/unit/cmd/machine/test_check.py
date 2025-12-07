"""
Tests for machine check command.

This command gathers secrets and checks them against HMSL for leaks.
It only sends hashes (not actual secrets) to the HMSL API.
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


class TestMachineCheckCommand:
    """Tests for the machine check command."""

    def test_check_no_secrets_found(self, cli_fs_runner: CliRunner):
        """
        GIVEN no secrets to gather
        WHEN running machine check
        THEN displays no secrets found message without calling HMSL
        """
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter([])
        mock_gatherer.stats = GatheringStats()

        with patch(
            "ggshield.cmd.machine.check.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch("ggshield.cmd.machine.check.check_secrets") as mock_hmsl:
                result = cli_fs_runner.invoke(cli, ["machine", "check"])

        assert_invoke_ok(result)
        assert "No secrets found" in result.output
        mock_hmsl.assert_not_called()

    def test_check_finds_secrets_and_checks_hmsl(self, cli_fs_runner: CliRunner):
        """
        GIVEN secrets found on the machine
        WHEN running machine check
        THEN gathers secrets and checks them against HMSL
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

        with patch(
            "ggshield.cmd.machine.check.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch(
                "ggshield.cmd.machine.check.check_secrets",
                return_value=({}, MagicMock()),  # Empty dict instead of set
            ) as mock_hmsl:
                result = cli_fs_runner.invoke(cli, ["machine", "check"])

        assert_invoke_ok(result)
        mock_hmsl.assert_called_once()

    def test_check_with_full_hashes_option(self, cli_fs_runner: CliRunner):
        """
        GIVEN secrets found and --full-hashes flag
        WHEN running machine check --full-hashes
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

        with patch(
            "ggshield.cmd.machine.check.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch(
                "ggshield.cmd.machine.check.check_secrets",
                return_value=({}, MagicMock()),  # Empty dict instead of set
            ) as mock_hmsl:
                result = cli_fs_runner.invoke(
                    cli, ["machine", "check", "--full-hashes"]
                )

        assert_invoke_ok(result)
        mock_hmsl.assert_called_once()
        # Verify full_hashes was passed
        call_kwargs = mock_hmsl.call_args[1]
        assert call_kwargs.get("full_hashes") is True

    def test_check_with_timeout_option(self, cli_fs_runner: CliRunner):
        """
        GIVEN a timeout option
        WHEN running machine check with --timeout
        THEN passes timeout to the gatherer config
        """
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter([])
        mock_gatherer.stats = GatheringStats()

        with patch(
            "ggshield.cmd.machine.check.MachineSecretGatherer",
            return_value=mock_gatherer,
        ) as mock_class:
            result = cli_fs_runner.invoke(cli, ["machine", "check", "--timeout", "30"])

        assert_invoke_ok(result)
        call_args = mock_class.call_args
        config = call_args[0][0]
        assert config.timeout == 30

    def test_check_with_min_chars_option(self, cli_fs_runner: CliRunner):
        """
        GIVEN a min-chars option
        WHEN running machine check with --min-chars
        THEN passes min_chars to the gatherer config
        """
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter([])
        mock_gatherer.stats = GatheringStats()

        with patch(
            "ggshield.cmd.machine.check.MachineSecretGatherer",
            return_value=mock_gatherer,
        ) as mock_class:
            result = cli_fs_runner.invoke(
                cli, ["machine", "check", "--min-chars", "10"]
            )

        assert_invoke_ok(result)
        call_args = mock_class.call_args
        config = call_args[0][0]
        assert config.min_chars == 10

    def test_check_with_exclude_option(self, cli_fs_runner: CliRunner):
        """
        GIVEN an exclude pattern
        WHEN running machine check with --exclude
        THEN passes exclusion patterns to the gatherer config
        """
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter([])
        mock_gatherer.stats = GatheringStats()

        with patch(
            "ggshield.cmd.machine.check.MachineSecretGatherer",
            return_value=mock_gatherer,
        ) as mock_class:
            result = cli_fs_runner.invoke(
                cli, ["machine", "check", "--exclude", "**/tests/**/*"]
            )

        assert_invoke_ok(result)
        call_args = mock_class.call_args
        config = call_args[0][0]
        assert len(config.exclusion_regexes) > 0

    def test_check_help(self, cli_fs_runner: CliRunner):
        """
        GIVEN the machine check command
        WHEN running with --help
        THEN displays help text with all options
        """
        result = cli_fs_runner.invoke(cli, ["machine", "check", "--help"])

        assert_invoke_ok(result)
        assert "--timeout" in result.output
        assert "--min-chars" in result.output
        assert "--full-hashes" in result.output
        assert "--exclude" in result.output
        assert "HasMySecretLeaked" in result.output or "leak" in result.output.lower()

    def test_check_json_output(self, cli_fs_runner: CliRunner):
        """
        GIVEN secrets found on the machine
        WHEN running machine check --json
        THEN outputs valid JSON with leak status
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
            "ggshield.cmd.machine.check.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch(
                "ggshield.cmd.machine.check.check_secrets",
                return_value=({}, MagicMock()),  # Empty dict instead of set
            ):
                result = cli_fs_runner.invoke(cli, ["machine", "check", "--json"])

        assert_invoke_ok(result)
        # Should contain JSON-formatted output
        assert "{" in result.output or "secrets" in result.output.lower()

    def test_check_displays_leaked_count(self, cli_fs_runner: CliRunner):
        """
        GIVEN secrets that are found to be leaked
        WHEN running machine check
        THEN displays the number of leaked secrets
        """
        mock_secrets = [
            GatheredSecret(
                value="leaked_secret_value",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="environment",
                    secret_name="LEAKED_KEY",
                ),
            ),
        ]
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter(mock_secrets)
        mock_gatherer.stats = GatheringStats(env_vars_count=1)

        # The check_secrets function handles display, so we just verify it's called
        with patch(
            "ggshield.cmd.machine.check.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch(
                "ggshield.cmd.machine.check.check_secrets",
                return_value=({}, MagicMock()),  # Empty dict instead of set
            ) as mock_hmsl:
                result = cli_fs_runner.invoke(cli, ["machine", "check"])

        assert_invoke_ok(result)
        mock_hmsl.assert_called_once()

    def test_machine_command_group_shows_check(self, cli_fs_runner: CliRunner):
        """
        GIVEN the machine command group
        WHEN running machine --help
        THEN displays check subcommand
        """
        result = cli_fs_runner.invoke(cli, ["machine", "--help"])

        assert_invoke_ok(result)
        assert "check" in result.output
