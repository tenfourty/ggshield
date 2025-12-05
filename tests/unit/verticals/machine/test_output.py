"""
Tests for machine scan output formatting.
"""

import json

from click.testing import CliRunner

from ggshield.verticals.machine.output import (
    _display_json_results,
    _display_text_results,
    _group_by_source,
    display_gathering_stats,
    display_scan_results,
)
from ggshield.verticals.machine.secret_gatherer import GatheringStats
from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)


class TestGroupBySource:
    """Tests for _group_by_source helper."""

    def test_groups_single_type(self):
        """
        GIVEN secrets of a single type
        WHEN grouping by source
        THEN returns correct count
        """
        secrets = [
            GatheredSecret(
                value="test",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="env",
                    secret_name="KEY",
                ),
            ),
            GatheredSecret(
                value="test2",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="env",
                    secret_name="KEY2",
                ),
            ),
        ]

        result = _group_by_source(secrets)

        assert result == {SourceType.ENVIRONMENT_VAR: 2}

    def test_groups_multiple_types(self):
        """
        GIVEN secrets of multiple types
        WHEN grouping by source
        THEN returns correct counts per type
        """
        secrets = [
            GatheredSecret(
                value="test",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="env",
                    secret_name="KEY",
                ),
            ),
            GatheredSecret(
                value="test2",
                metadata=SecretMetadata(
                    source_type=SourceType.PRIVATE_KEY,
                    source_path="/path",
                    secret_name="id_rsa",
                ),
            ),
            GatheredSecret(
                value="test3",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="env",
                    secret_name="KEY2",
                ),
            ),
        ]

        result = _group_by_source(secrets)

        assert result == {SourceType.ENVIRONMENT_VAR: 2, SourceType.PRIVATE_KEY: 1}

    def test_groups_empty_list(self):
        """
        GIVEN no secrets
        WHEN grouping by source
        THEN returns empty dict
        """
        result = _group_by_source([])

        assert result == {}


class TestDisplayJsonResults:
    """Tests for JSON output formatting."""

    def test_json_output_structure(self, capsys):
        """
        GIVEN secrets from multiple sources
        WHEN displaying JSON results
        THEN outputs valid JSON with correct structure
        """
        secrets = [
            GatheredSecret(
                value="test",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="env",
                    secret_name="KEY",
                ),
            ),
            GatheredSecret(
                value="test2",
                metadata=SecretMetadata(
                    source_type=SourceType.PRIVATE_KEY,
                    source_path="/path",
                    secret_name="id_rsa",
                ),
            ),
        ]

        runner = CliRunner()
        with runner.isolated_filesystem():
            _display_json_results(secrets)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert data["secrets_found"] == 2
        assert "Environment variables" in data["sources"]
        assert "Private keys" in data["sources"]
        assert data["sources"]["Environment variables"] == 1
        assert data["sources"]["Private keys"] == 1

    def test_json_output_empty_secrets(self, capsys):
        """
        GIVEN no secrets
        WHEN displaying JSON results
        THEN outputs JSON with zero count
        """
        runner = CliRunner()
        with runner.isolated_filesystem():
            _display_json_results([])

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert data["secrets_found"] == 0
        assert data["sources"] == {}


class TestDisplayTextResults:
    """Tests for text output formatting."""

    def test_text_output_with_secrets(self, capsys):
        """
        GIVEN secrets from multiple sources
        WHEN displaying text results
        THEN shows human-readable summary
        """
        secrets = [
            GatheredSecret(
                value="test",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="env",
                    secret_name="KEY",
                ),
            ),
            GatheredSecret(
                value="test2",
                metadata=SecretMetadata(
                    source_type=SourceType.PRIVATE_KEY,
                    source_path="/path",
                    secret_name="id_rsa",
                ),
            ),
        ]

        _display_text_results(secrets)

        captured = capsys.readouterr()
        output = captured.out + captured.err  # ui module writes to stderr
        assert "Found 2 potential secrets" in output
        assert "By source:" in output
        assert "Environment variables" in output
        assert "Private keys" in output
        assert "--check" in output

    def test_text_output_sorted_by_count(self, capsys):
        """
        GIVEN secrets with different counts per source
        WHEN displaying text results
        THEN shows sources sorted by count (highest first)
        """
        secrets = [
            GatheredSecret(
                value="test1",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="env",
                    secret_name="KEY1",
                ),
            ),
            GatheredSecret(
                value="test2",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="env",
                    secret_name="KEY2",
                ),
            ),
            GatheredSecret(
                value="test3",
                metadata=SecretMetadata(
                    source_type=SourceType.PRIVATE_KEY,
                    source_path="/path",
                    secret_name="id_rsa",
                ),
            ),
        ]

        _display_text_results(secrets)

        captured = capsys.readouterr()
        output = captured.out + captured.err  # ui module writes to stderr
        # Environment variables (2) should appear before Private keys (1)
        env_pos = output.find("Environment variables")
        key_pos = output.find("Private keys")
        assert env_pos < key_pos


class TestDisplayScanResults:
    """Tests for display_scan_results dispatcher."""

    def test_dispatches_to_json(self, capsys):
        """
        GIVEN json_output=True
        WHEN calling display_scan_results
        THEN outputs JSON format
        """
        secrets = [
            GatheredSecret(
                value="test",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="env",
                    secret_name="KEY",
                ),
            ),
        ]

        runner = CliRunner()
        with runner.isolated_filesystem():
            display_scan_results(secrets, json_output=True)

        captured = capsys.readouterr()
        # Should be valid JSON
        data = json.loads(captured.out)
        assert "secrets_found" in data

    def test_dispatches_to_text(self, capsys):
        """
        GIVEN json_output=False
        WHEN calling display_scan_results
        THEN outputs text format
        """
        secrets = [
            GatheredSecret(
                value="test",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="env",
                    secret_name="KEY",
                ),
            ),
        ]

        display_scan_results(secrets, json_output=False)

        captured = capsys.readouterr()
        output = captured.out + captured.err  # ui module writes to stderr
        assert "Found 1 potential secret" in output


class TestDisplayGatheringStats:
    """Tests for display_gathering_stats function."""

    def test_displays_all_sources(self, capsys):
        """
        GIVEN stats with all source types
        WHEN displaying gathering stats
        THEN shows all source information
        """
        stats = GatheringStats(
            env_vars_count=5,
            github_token_found=True,
            npmrc_files=1,
            npmrc_secrets=2,
            env_files=3,
            env_secrets=4,
            private_key_files=2,
            private_key_secrets=2,
            total_files_visited=1000,
            elapsed_seconds=5.5,
        )

        display_gathering_stats(stats, json_output=False)

        captured = capsys.readouterr()
        output = captured.out + captured.err  # ui module writes to stderr
        assert "Sources scanned:" in output
        assert "Environment variables: 5" in output
        assert "GitHub token: found" in output
        assert "NPM configuration: 1 file" in output
        assert "Environment files: 3 files" in output
        assert "Private keys: 2 files" in output
        assert "Total files visited: 1000" in output
        assert "5.5s" in output

    def test_displays_github_not_found(self, capsys):
        """
        GIVEN stats with github_token_found=False
        WHEN displaying gathering stats
        THEN shows 'not found' for GitHub
        """
        stats = GatheringStats(github_token_found=False)

        display_gathering_stats(stats, json_output=False)

        captured = capsys.readouterr()
        output = captured.out + captured.err  # ui module writes to stderr
        assert "GitHub token: not found" in output

    def test_displays_no_npmrc(self, capsys):
        """
        GIVEN stats with no npmrc files
        WHEN displaying gathering stats
        THEN shows 'no .npmrc found'
        """
        stats = GatheringStats(npmrc_files=0)

        display_gathering_stats(stats, json_output=False)

        captured = capsys.readouterr()
        output = captured.out + captured.err  # ui module writes to stderr
        assert "no .npmrc found" in output

    def test_displays_timeout_warning(self, capsys):
        """
        GIVEN stats with timed_out=True
        WHEN displaying gathering stats
        THEN shows timeout warning
        """
        stats = GatheringStats(timed_out=True)

        display_gathering_stats(stats, json_output=False)

        captured = capsys.readouterr()
        output = captured.out + captured.err  # ui module writes to stderr
        assert "timed out" in output.lower()

    def test_json_output_skips_display(self, capsys):
        """
        GIVEN json_output=True
        WHEN displaying gathering stats
        THEN outputs nothing (JSON is handled elsewhere)
        """
        stats = GatheringStats(env_vars_count=5)

        display_gathering_stats(stats, json_output=True)

        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert output == ""

    def test_skips_total_when_zero(self, capsys):
        """
        GIVEN stats with total_files_visited=0
        WHEN displaying gathering stats
        THEN skips total files line
        """
        stats = GatheringStats(total_files_visited=0)

        display_gathering_stats(stats, json_output=False)

        captured = capsys.readouterr()
        output = captured.out + captured.err  # ui module writes to stderr
        assert "Total files visited" not in output
