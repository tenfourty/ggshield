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
        # Check individual secrets are included
        assert "secrets" in data
        assert len(data["secrets"]) == 2
        assert data["secrets"][0]["source_type"] == "Environment variables"
        assert data["secrets"][0]["source_path"] == "env"
        assert data["secrets"][0]["secret_name"] == "KEY"

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
        assert "── Summary ──" in output
        assert "Environment variables" in output
        assert "Private keys" in output
        assert "machine check" in output

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
            github_token_found=True,
            total_files_visited=1000,
            elapsed_seconds=5.5,
        )
        # Set counts using the new dict-based approach
        stats.increment_secrets(SourceType.ENVIRONMENT_VAR, 5)
        stats.increment_files(SourceType.NPMRC, 1)
        stats.increment_secrets(SourceType.NPMRC, 2)
        stats.increment_files(SourceType.ENV_FILE, 3)
        stats.increment_secrets(SourceType.ENV_FILE, 4)
        stats.increment_files(SourceType.PRIVATE_KEY, 2)
        stats.increment_secrets(SourceType.PRIVATE_KEY, 2)

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
        stats = GatheringStats()
        # npmrc_files defaults to 0 with the new dict-based approach

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
        stats = GatheringStats()
        stats.increment_secrets(SourceType.ENVIRONMENT_VAR, 5)

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


class TestDisplayVerboseTextResults:
    """Tests for verbose text output formatting."""

    def test_verbose_output_with_secrets(self, capsys):
        """
        GIVEN secrets from multiple sources
        WHEN displaying verbose results
        THEN shows detailed per-secret information
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
                    source_path="/path/to/id_rsa",
                    secret_name="id_rsa",
                ),
            ),
        ]

        display_scan_results(secrets, json_output=False, verbose=True)

        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert "Found 2 potential secrets" in output
        assert "── Summary ──" in output
        assert "── Details ──" in output
        assert "Environment variables" in output
        assert "Private keys" in output
        # Verbose shows individual secret paths
        assert "env:KEY" in output
        assert "/path/to/id_rsa" in output

    def test_verbose_output_with_deep_scan_secrets(self, capsys):
        """
        GIVEN secrets from deep scan
        WHEN displaying verbose results
        THEN groups by detector type
        """
        secrets = [
            GatheredSecret(
                value="ghp_xxxxxxxxxxxx",
                metadata=SecretMetadata(
                    source_type=SourceType.DEEP_SCAN,
                    source_path="/path/to/file.txt",
                    secret_name="GitHub Token",
                ),
            ),
            GatheredSecret(
                value="AKIAIOSFODNN7EXAMPLE",
                metadata=SecretMetadata(
                    source_type=SourceType.DEEP_SCAN,
                    source_path="/path/to/config",
                    secret_name="AWS Access Key",
                ),
            ),
        ]

        display_scan_results(secrets, json_output=False, verbose=True)

        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert "Found 2 potential secrets" in output
        assert "[GitHub Token]" in output
        assert "[AWS Access Key]" in output


class TestDisplayHmslCheckResults:
    """Tests for HMSL check output formatting."""

    def test_text_hmsl_no_leaked(self, capsys):
        """
        GIVEN secrets with none leaked
        WHEN displaying HMSL results
        THEN shows all clear message
        """
        from ggshield.verticals.machine.output import display_hmsl_check_results

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
        leaked_info = {}  # No leaked secrets

        display_hmsl_check_results(secrets, leaked_info, json_output=False)

        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert "No leaked secrets found" in output
        assert "1 checked" in output

    def test_text_hmsl_with_leaked(self, capsys):
        """
        GIVEN secrets with some leaked
        WHEN displaying HMSL results
        THEN shows leaked count
        """
        from ggshield.verticals.machine.output import (
            LeakedSecretInfo,
            display_hmsl_check_results,
        )

        secrets = [
            GatheredSecret(
                value="leaked_secret",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="env",
                    secret_name="KEY",
                ),
            ),
        ]
        leaked_info = {
            "KEY (env)": LeakedSecretInfo(
                key="KEY (env)",
                count=5,
                url="https://example.com",
                secret_value="leaked_secret",
            )
        }

        display_hmsl_check_results(secrets, leaked_info, json_output=False)

        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert "Found 1 leaked secret" in output

    def test_json_hmsl_output(self, capsys):
        """
        GIVEN secrets with leaked info
        WHEN displaying HMSL results as JSON
        THEN outputs valid JSON with leaked info
        """
        from click.testing import CliRunner

        from ggshield.verticals.machine.output import (
            LeakedSecretInfo,
            display_hmsl_check_results,
        )

        secrets = [
            GatheredSecret(
                value="leaked_secret",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="env",
                    secret_name="KEY",
                ),
            ),
        ]
        leaked_info = {
            "KEY (env)": LeakedSecretInfo(
                key="KEY (env)",
                count=5,
                url="https://example.com",
                secret_value="leaked_secret",
            )
        }

        runner = CliRunner()
        with runner.isolated_filesystem():
            display_hmsl_check_results(secrets, leaked_info, json_output=True)

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["secrets_checked"] == 1
        assert data["leaked_count"] == 1
        assert len(data["secrets"]) == 1
        assert data["secrets"][0]["leaked"] is True
        assert data["secrets"][0]["leak_info"]["occurrences"] == 5

    def test_verbose_hmsl_with_priority_tiers(self, capsys):
        """
        GIVEN leaked secrets with different occurrence counts
        WHEN displaying verbose HMSL results
        THEN groups by priority tier
        """
        from ggshield.verticals.machine.output import (
            LeakedSecretInfo,
            display_hmsl_check_results,
        )

        secrets = [
            GatheredSecret(
                value="high_priority_secret",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="env",
                    secret_name="HIGH",
                ),
            ),
            GatheredSecret(
                value="medium_priority_secret",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="env",
                    secret_name="MEDIUM",
                ),
            ),
            GatheredSecret(
                value="not_leaked",
                metadata=SecretMetadata(
                    source_type=SourceType.ENVIRONMENT_VAR,
                    source_path="env",
                    secret_name="SAFE",
                ),
            ),
        ]
        leaked_info = {
            "HIGH (env)": LeakedSecretInfo(
                key="HIGH (env)",
                count=3,  # < 10 = high priority
                url="https://example.com",
                secret_value="high_priority_secret",
            ),
            "MEDIUM (env)": LeakedSecretInfo(
                key="MEDIUM (env)",
                count=50,  # 10-99 = medium priority
                url="https://example.com",
                secret_value="medium_priority_secret",
            ),
        }

        display_hmsl_check_results(
            secrets, leaked_info, json_output=False, verbose=True
        )

        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert "HIGH PRIORITY" in output
        assert "MEDIUM PRIORITY" in output
        assert "── Leaked Secrets ──" in output
        assert "── Not Leaked ──" in output
        assert "[OK]" in output  # For the non-leaked secret


class TestDisplayAnalyzedResults:
    """Tests for analysis output formatting."""

    def test_text_analyzed_results(self, capsys):
        """
        GIVEN analyzed secrets
        WHEN displaying text results
        THEN shows summary by detector type
        """
        from ggshield.verticals.machine.analyzer import AnalysisResult, AnalyzedSecret
        from ggshield.verticals.machine.output import display_analyzed_results

        gathered = GatheredSecret(
            value="ghp_xxxxxxxxxxxx",
            metadata=SecretMetadata(
                source_type=SourceType.GITHUB_TOKEN,
                source_path="/path",
                secret_name="token",
            ),
        )
        analyzed = AnalyzedSecret(
            gathered_secret=gathered,
            detector_name="github_token",
            detector_display_name="GitHub Token",
            validity="valid",
            known_secret=False,
            incident_url=None,
        )
        result = AnalysisResult(
            analyzed_secrets=[analyzed],
            errors=[],
        )

        display_analyzed_results(result, json_output=False)

        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert "Analysis Results" in output
        assert "1 secret" in output
        assert "GitHub Token" in output
        assert "valid" in output.lower()

    def test_json_analyzed_results(self, capsys):
        """
        GIVEN analyzed secrets
        WHEN displaying JSON results
        THEN outputs valid JSON with analysis info
        """
        from click.testing import CliRunner

        from ggshield.verticals.machine.analyzer import AnalysisResult, AnalyzedSecret
        from ggshield.verticals.machine.output import display_analyzed_results

        gathered = GatheredSecret(
            value="ghp_xxxxxxxxxxxx",
            metadata=SecretMetadata(
                source_type=SourceType.GITHUB_TOKEN,
                source_path="/path",
                secret_name="token",
            ),
        )
        analyzed = AnalyzedSecret(
            gathered_secret=gathered,
            detector_name="github_token",
            detector_display_name="GitHub Token",
            validity="valid",
            known_secret=False,
            incident_url="https://dashboard.example.com/1",
        )
        result = AnalysisResult(
            analyzed_secrets=[analyzed],
            errors=[],
        )

        runner = CliRunner()
        with runner.isolated_filesystem():
            display_analyzed_results(result, json_output=True)

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["secrets_analyzed"] == 1
        assert data["detected_count"] == 1
        assert len(data["secrets"]) == 1
        assert data["secrets"][0]["detector"] == "GitHub Token"
        assert data["secrets"][0]["validity"] == "valid"

    def test_analyzed_results_with_errors(self, capsys):
        """
        GIVEN analysis result with errors
        WHEN displaying text results
        THEN shows error warnings
        """
        from ggshield.verticals.machine.analyzer import AnalysisResult
        from ggshield.verticals.machine.output import display_analyzed_results

        result = AnalysisResult(
            analyzed_secrets=[],
            errors=["API rate limit exceeded", "Network timeout"],
        )

        display_analyzed_results(result, json_output=False)

        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert "API rate limit exceeded" in output
        assert "Network timeout" in output

    def test_analyzed_results_with_known_secrets(self, capsys):
        """
        GIVEN analyzed secrets with some marked as known
        WHEN displaying text results
        THEN shows known secrets count
        """
        from ggshield.verticals.machine.analyzer import AnalysisResult, AnalyzedSecret
        from ggshield.verticals.machine.output import display_analyzed_results

        gathered = GatheredSecret(
            value="ghp_xxxxxxxxxxxx",
            metadata=SecretMetadata(
                source_type=SourceType.GITHUB_TOKEN,
                source_path="/path",
                secret_name="token",
            ),
        )
        analyzed = AnalyzedSecret(
            gathered_secret=gathered,
            detector_name="github_token",
            detector_display_name="GitHub Token",
            validity="valid",
            known_secret=True,
            incident_url="https://dashboard.example.com/1",
        )
        result = AnalysisResult(
            analyzed_secrets=[analyzed],
            errors=[],
        )

        display_analyzed_results(result, json_output=False)

        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert "Known secrets: 1" in output
        assert "already tracked" in output
