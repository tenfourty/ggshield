"""
Tests for machine ping command.

This command tests connectivity to the GitGuardian platform.
"""

from unittest.mock import MagicMock, patch

import requests
from click.testing import CliRunner

from ggshield.__main__ import cli
from ggshield.verticals.machine.inventory import NHIAuthError
from tests.unit.conftest import assert_invoke_exited_with, assert_invoke_ok


class TestMachinePingCommand:
    """Tests for the machine ping command."""

    def test_ping_success(self, cli_fs_runner: CliRunner):
        """
        GIVEN valid API credentials
        WHEN running machine ping
        THEN displays success message
        """
        mock_client = MagicMock()
        mock_client.ping.return_value = {}

        with patch(
            "ggshield.cmd.machine.ping.InventoryClient",
            return_value=mock_client,
        ):
            result = cli_fs_runner.invoke(cli, ["machine", "ping"])

        assert_invoke_ok(result)
        assert "Connection successful" in result.output
        mock_client.ping.assert_called_once()

    def test_ping_failure_returns_error(self, cli_fs_runner: CliRunner):
        """
        GIVEN invalid API credentials
        WHEN running machine ping
        THEN displays error message and returns error exit code
        """
        mock_client = MagicMock()
        mock_client.ping.side_effect = requests.HTTPError("401 Unauthorized")

        with patch(
            "ggshield.cmd.machine.ping.InventoryClient",
            return_value=mock_client,
        ):
            result = cli_fs_runner.invoke(cli, ["machine", "ping"])

        assert_invoke_exited_with(result, 128)
        assert "Connection failed" in result.output

    def test_ping_with_source_name_option(self, cli_fs_runner: CliRunner):
        """
        GIVEN --source-name option
        WHEN running machine ping --source-name my-server
        THEN uses provided name and displays it
        """
        mock_client = MagicMock()
        mock_client.ping.return_value = {}

        with patch(
            "ggshield.cmd.machine.ping.InventoryClient",
            return_value=mock_client,
        ):
            result = cli_fs_runner.invoke(
                cli, ["machine", "ping", "--source-name", "my-server"]
            )

        assert_invoke_ok(result)
        assert "my-server" in result.output
        mock_client.ping.assert_called_once_with("my-server", env="development")

    def test_ping_with_env_option(self, cli_fs_runner: CliRunner):
        """
        GIVEN --env option
        WHEN running machine ping --env production
        THEN sends production environment to API
        """
        mock_client = MagicMock()
        mock_client.ping.return_value = {}

        with patch(
            "ggshield.cmd.machine.ping.InventoryClient",
            return_value=mock_client,
        ):
            result = cli_fs_runner.invoke(
                cli, ["machine", "ping", "--env", "production"]
            )

        assert_invoke_ok(result)
        assert "production" in result.output
        # Check that env was passed to ping
        call_args = mock_client.ping.call_args
        assert call_args[1]["env"] == "production"

    def test_ping_help(self, cli_fs_runner: CliRunner):
        """
        GIVEN the machine ping command
        WHEN running with --help
        THEN displays help text
        """
        result = cli_fs_runner.invoke(cli, ["machine", "ping", "--help"])

        assert_invoke_ok(result)
        assert "Test connectivity" in result.output
        assert "--source-name" in result.output
        assert "--env" in result.output

    def test_machine_command_group_shows_ping(self, cli_fs_runner: CliRunner):
        """
        GIVEN the machine command group
        WHEN running machine --help
        THEN displays ping subcommand
        """
        result = cli_fs_runner.invoke(cli, ["machine", "--help"])

        assert_invoke_ok(result)
        assert "ping" in result.output

    def test_ping_nhi_auth_error_displays_helpful_message(
        self, cli_fs_runner: CliRunner
    ):
        """
        GIVEN an NHIAuthError (e.g., 404 from missing scope)
        WHEN running machine ping
        THEN displays the helpful error message
        """
        mock_client = MagicMock()
        mock_client.ping.side_effect = NHIAuthError(
            "NHI endpoint not found. Ensure your API key has 'nhi:send-inventory' scope."
        )

        with patch(
            "ggshield.cmd.machine.ping.InventoryClient",
            return_value=mock_client,
        ):
            result = cli_fs_runner.invoke(cli, ["machine", "ping"])

        assert_invoke_exited_with(result, 128)
        assert "nhi:send-inventory" in result.output

    def test_ping_help_shows_authentication_info(self, cli_fs_runner: CliRunner):
        """
        GIVEN the machine ping command
        WHEN running with --help
        THEN displays authentication requirements
        """
        result = cli_fs_runner.invoke(cli, ["machine", "ping", "--help"])

        assert_invoke_ok(result)
        assert "AUTHENTICATION" in result.output
        assert "nhi:send-inventory" in result.output
        assert "GITGUARDIAN_NHI_API_KEY" in result.output
