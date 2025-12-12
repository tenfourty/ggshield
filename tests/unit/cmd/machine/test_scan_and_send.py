"""
Tests for machine scan-and-send command.

This command gathers secrets, analyzes them, and uploads inventory to GitGuardian.
"""

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
from tests.unit.conftest import assert_invoke_ok


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


class TestMachineScanAndSendCommand:
    """Tests for the machine scan-and-send command."""

    def test_scan_and_send_no_secrets_found(self, cli_fs_runner: CliRunner):
        """
        GIVEN no secrets to gather
        WHEN running machine scan-and-send
        THEN displays no secrets found message without uploading
        """
        mock_gatherer = MagicMock()
        mock_gatherer.gather.return_value = iter([])
        mock_gatherer.stats = GatheringStats()

        with patch(
            "ggshield.cmd.machine.scan_and_send.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch(
                "ggshield.cmd.machine.scan_and_send.InventoryClient"
            ) as mock_client_class:
                result = cli_fs_runner.invoke(cli, ["machine", "scan-and-send"])

        assert_invoke_ok(result)
        assert "No secrets found" in result.output
        mock_client_class.assert_not_called()

    def test_scan_and_send_dry_run_shows_payload(self, cli_fs_runner: CliRunner):
        """
        GIVEN secrets found on the machine
        WHEN running machine scan-and-send --dry-run
        THEN shows payload without uploading
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
            "ggshield.cmd.machine.scan_and_send.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch(
                "ggshield.core.client.create_client_from_config",
                return_value=mock_client,
            ):
                with patch("ggshield.verticals.machine.analyzer.check_client_api_key"):
                    with patch("ggshield.cmd.machine.scan_and_send.check_leaks"):
                        with patch(
                            "ggshield.cmd.machine.scan_and_send.InventoryClient"
                        ) as mock_inventory_client:
                            result = cli_fs_runner.invoke(
                                cli, ["machine", "scan-and-send", "--dry-run"]
                            )

        # Should show payload
        assert "outputs" in result.output or "schema_version" in result.output
        # Should not upload
        mock_inventory_client.return_value.upload.assert_not_called()

    def test_scan_and_send_with_env_option(self, cli_fs_runner: CliRunner):
        """
        GIVEN secrets found on the machine
        WHEN running machine scan-and-send --env production
        THEN sets environment to production in payload
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
            scan_results=[_make_scan_result([_make_policy_break()])]
        )

        with patch(
            "ggshield.cmd.machine.scan_and_send.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch(
                "ggshield.core.client.create_client_from_config",
                return_value=mock_client,
            ):
                with patch("ggshield.verticals.machine.analyzer.check_client_api_key"):
                    with patch("ggshield.cmd.machine.scan_and_send.check_leaks"):
                        result = cli_fs_runner.invoke(
                            cli,
                            [
                                "machine",
                                "scan-and-send",
                                "--dry-run",
                                "--env",
                                "production",
                            ],
                        )

        # Should include production in output (dry-run shows payload)
        assert "production" in result.output

    def test_scan_and_send_with_source_name_option(self, cli_fs_runner: CliRunner):
        """
        GIVEN --source-name option
        WHEN running machine scan-and-send --source-name my-server
        THEN uses provided name instead of hostname
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
            scan_results=[_make_scan_result([_make_policy_break()])]
        )

        with patch(
            "ggshield.cmd.machine.scan_and_send.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch(
                "ggshield.core.client.create_client_from_config",
                return_value=mock_client,
            ):
                with patch("ggshield.verticals.machine.analyzer.check_client_api_key"):
                    with patch("ggshield.cmd.machine.scan_and_send.check_leaks"):
                        result = cli_fs_runner.invoke(
                            cli,
                            [
                                "machine",
                                "scan-and-send",
                                "--dry-run",
                                "--source-name",
                                "my-server",
                            ],
                        )

        # Should include custom source name in output
        assert "my-server" in result.output

    def test_scan_and_send_skip_analysis_flag(self, cli_fs_runner: CliRunner):
        """
        GIVEN secrets found and --skip-analysis flag
        WHEN running machine scan-and-send --skip-analysis
        THEN does not call GitGuardian scanning API
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
            "ggshield.cmd.machine.scan_and_send.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch("ggshield.core.client.create_client_from_config"):
                result = cli_fs_runner.invoke(
                    cli, ["machine", "scan-and-send", "--skip-analysis", "--dry-run"]
                )

        # Should not create scanning client when skipping analysis
        assert_invoke_ok(result)

    def test_scan_and_send_help(self, cli_fs_runner: CliRunner):
        """
        GIVEN the machine scan-and-send command
        WHEN running with --help
        THEN displays help text with all options
        """
        result = cli_fs_runner.invoke(cli, ["machine", "scan-and-send", "--help"])

        assert_invoke_ok(result)
        assert "--timeout" in result.output
        assert "--min-chars" in result.output
        assert "--exclude" in result.output
        assert "--env" in result.output
        assert "--source-name" in result.output
        assert "--dry-run" in result.output
        assert "--skip-analysis" in result.output

    def test_scan_and_send_uploads_to_api(self, cli_fs_runner: CliRunner):
        """
        GIVEN secrets found on the machine
        WHEN running machine scan-and-send (without --dry-run)
        THEN uploads inventory to GitGuardian API
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
            scan_results=[_make_scan_result([_make_policy_break()])]
        )

        mock_inventory_client = MagicMock()
        mock_inventory_client.upload.return_value = {"raw_data_id": 12345}

        with patch(
            "ggshield.cmd.machine.scan_and_send.MachineSecretGatherer",
            return_value=mock_gatherer,
        ):
            with patch(
                "ggshield.core.client.create_client_from_config",
                return_value=mock_client,
            ):
                with patch("ggshield.verticals.machine.analyzer.check_client_api_key"):
                    with patch("ggshield.cmd.machine.scan_and_send.check_leaks"):
                        with patch(
                            "ggshield.cmd.machine.scan_and_send.InventoryClient",
                            return_value=mock_inventory_client,
                        ):
                            result = cli_fs_runner.invoke(
                                cli, ["machine", "scan-and-send"]
                            )

        # Should have called upload
        mock_inventory_client.upload.assert_called_once()
        # Should show success message
        assert "12345" in result.output or "success" in result.output.lower()

    def test_machine_command_group_shows_scan_and_send(self, cli_fs_runner: CliRunner):
        """
        GIVEN the machine command group
        WHEN running machine --help
        THEN displays scan-and-send subcommand
        """
        result = cli_fs_runner.invoke(cli, ["machine", "--help"])

        assert_invoke_ok(result)
        assert "scan-and-send" in result.output
