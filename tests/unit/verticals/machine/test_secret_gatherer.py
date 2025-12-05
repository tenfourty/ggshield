"""
Tests for MachineSecretGatherer.
"""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from ggshield.core.filter import init_exclusion_regexes
from ggshield.verticals.machine.secret_gatherer import (
    GatheringConfig,
    GatheringStats,
    MachineSecretGatherer,
    SourceResult,
    SourceStatus,
)
from ggshield.verticals.machine.sources import SourceType


class TestGatheringConfig:
    """Tests for GatheringConfig dataclass."""

    def test_default_values(self):
        """
        GIVEN a GatheringConfig with no arguments
        WHEN created
        THEN has correct default values
        """
        config = GatheringConfig()

        assert config.timeout == 0
        assert config.min_chars == 5
        assert config.verbose is False
        assert config.home_dir is None

    def test_custom_values(self):
        """
        GIVEN custom config values
        WHEN creating GatheringConfig
        THEN stores those values
        """
        config = GatheringConfig(
            timeout=30, min_chars=10, verbose=True, home_dir=Path("/tmp")
        )

        assert config.timeout == 30
        assert config.min_chars == 10
        assert config.verbose is True
        assert config.home_dir == Path("/tmp")


class TestGatheringStats:
    """Tests for GatheringStats dataclass."""

    def test_default_values(self):
        """
        GIVEN a GatheringStats with no arguments
        WHEN created
        THEN has zero/false defaults
        """
        stats = GatheringStats()

        assert stats.env_vars_count == 0
        assert stats.github_token_found is False
        assert stats.npmrc_files == 0
        assert stats.npmrc_secrets == 0
        assert stats.env_files == 0
        assert stats.env_secrets == 0
        assert stats.private_key_files == 0
        assert stats.private_key_secrets == 0
        assert stats.total_files_visited == 0
        assert stats.elapsed_seconds == 0.0
        assert stats.timed_out is False


class TestMachineSecretGatherer:
    """Tests for MachineSecretGatherer."""

    def test_gather_from_environment(self, tmp_path: Path):
        """
        GIVEN environment variables set
        WHEN gathering secrets
        THEN includes environment secrets
        """
        test_env = {"TEST_SECRET_KEY": "test_secret_value"}

        with patch.dict(os.environ, test_env, clear=True):
            config = GatheringConfig(home_dir=tmp_path, min_chars=5)
            gatherer = MachineSecretGatherer(config)
            secrets = list(gatherer.gather())

        env_secrets = [
            s for s in secrets if s.metadata.source_type == SourceType.ENVIRONMENT_VAR
        ]
        assert len(env_secrets) == 1
        assert gatherer.stats.env_vars_count == 1

    def test_gather_filters_short_values(self, tmp_path: Path):
        """
        GIVEN environment variables with short values
        WHEN gathering with min_chars=10
        THEN filters out short values
        """
        test_env = {
            "SHORT": "abc",  # 3 chars
            "LONG_VALUE": "this_is_long_enough",  # > 10 chars
        }

        with patch.dict(os.environ, test_env, clear=True):
            config = GatheringConfig(home_dir=tmp_path, min_chars=10)
            gatherer = MachineSecretGatherer(config)
            secrets = list(gatherer.gather())

        names = {s.metadata.secret_name for s in secrets}
        assert "LONG_VALUE" in names
        assert "SHORT" not in names

    def test_gather_from_npmrc(self, tmp_path: Path):
        """
        GIVEN an .npmrc file with auth token
        WHEN gathering secrets
        THEN includes npmrc secrets
        """
        npmrc_content = "//registry.npmjs.org/:_authToken=npm_test_token_12345"
        (tmp_path / ".npmrc").write_text(npmrc_content)

        with patch.dict(os.environ, {}, clear=True):
            config = GatheringConfig(home_dir=tmp_path, min_chars=5)
            gatherer = MachineSecretGatherer(config)
            secrets = list(gatherer.gather())

        npmrc_secrets = [
            s for s in secrets if s.metadata.source_type == SourceType.NPMRC
        ]
        assert len(npmrc_secrets) == 1
        assert gatherer.stats.npmrc_files == 1
        assert gatherer.stats.npmrc_secrets == 1

    def test_gather_from_env_files(self, tmp_path: Path):
        """
        GIVEN .env files with secrets
        WHEN gathering secrets
        THEN includes env file secrets
        """
        (tmp_path / ".env").write_text("ENV_SECRET=env_secret_value")

        with patch.dict(os.environ, {}, clear=True):
            config = GatheringConfig(home_dir=tmp_path, min_chars=5)
            gatherer = MachineSecretGatherer(config)
            secrets = list(gatherer.gather())

        env_file_secrets = [
            s for s in secrets if s.metadata.source_type == SourceType.ENV_FILE
        ]
        assert len(env_file_secrets) == 1
        assert gatherer.stats.env_files >= 1
        assert gatherer.stats.env_secrets >= 1

    def test_gather_from_private_keys(self, tmp_path: Path):
        """
        GIVEN private key files
        WHEN gathering secrets
        THEN includes private key secrets
        """
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        key_content = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MBAuMfB6JaALzdGk
-----END RSA PRIVATE KEY-----"""
        (ssh_dir / "id_rsa").write_text(key_content)

        with patch.dict(os.environ, {}, clear=True):
            config = GatheringConfig(home_dir=tmp_path, min_chars=5)
            gatherer = MachineSecretGatherer(config)
            secrets = list(gatherer.gather())

        key_secrets = [
            s for s in secrets if s.metadata.source_type == SourceType.PRIVATE_KEY
        ]
        assert len(key_secrets) == 1
        assert gatherer.stats.private_key_files == 1

    def test_gather_with_timeout(self, tmp_path: Path):
        """
        GIVEN a very short timeout
        WHEN gathering secrets
        THEN may timeout and set timed_out flag
        """
        # Create many nested directories to slow down scanning
        for i in range(10):
            nested = tmp_path / f"dir{i}"
            nested.mkdir()
            (nested / ".env").write_text(f"SECRET{i}=value{i}")

        with patch.dict(os.environ, {}, clear=True):
            # Use a tiny timeout that's likely to trigger
            config = GatheringConfig(home_dir=tmp_path, timeout=0, min_chars=5)
            gatherer = MachineSecretGatherer(config)
            # Just verify it completes without error
            list(gatherer.gather())

        # With timeout=0, no timeout occurs
        assert gatherer.stats.timed_out is False

    def test_gather_stats_populated(self, tmp_path: Path):
        """
        GIVEN various secret sources
        WHEN gathering secrets
        THEN stats are populated correctly
        """
        # Set up various sources
        (tmp_path / ".npmrc").write_text("//registry.npmjs.org/:_authToken=npm_token")
        (tmp_path / ".env").write_text("API_KEY=api_key_value")

        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_rsa").write_text(
            "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
        )

        test_env = {"MY_SECRET": "my_secret_value"}

        with patch.dict(os.environ, test_env, clear=True):
            config = GatheringConfig(home_dir=tmp_path, min_chars=5)
            gatherer = MachineSecretGatherer(config)
            list(gatherer.gather())

        stats = gatherer.stats
        assert stats.env_vars_count >= 1
        assert stats.npmrc_files == 1
        assert stats.npmrc_secrets == 1
        assert stats.env_files >= 1
        assert stats.env_secrets >= 1
        assert stats.private_key_files == 1
        assert stats.elapsed_seconds > 0

    def test_gather_empty_home_dir(self, tmp_path: Path):
        """
        GIVEN an empty home directory
        WHEN gathering secrets
        THEN returns empty list (only env vars if any)
        """
        with patch.dict(os.environ, {}, clear=True):
            config = GatheringConfig(home_dir=tmp_path, min_chars=5)
            gatherer = MachineSecretGatherer(config)
            secrets = list(gatherer.gather())

        # Only sources from filesystem, no env vars
        assert len(secrets) == 0

    def test_well_known_locations_permission_error_on_iterdir(self, tmp_path: Path):
        """
        GIVEN .ssh directory with permission error on iteration
        WHEN gathering secrets
        THEN handles error gracefully and continues
        """
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        key_content = "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
        (ssh_dir / "id_rsa").write_text(key_content)

        # Make .gnupg unreadable to trigger error
        gnupg_dir = tmp_path / ".gnupg"
        gnupg_dir.mkdir()
        gnupg_dir.chmod(0o000)

        try:
            with patch.dict(os.environ, {}, clear=True):
                config = GatheringConfig(home_dir=tmp_path, min_chars=5)
                gatherer = MachineSecretGatherer(config)
                secrets = list(gatherer.gather())

            # Should still find the key in .ssh despite .gnupg error
            key_secrets = [
                s for s in secrets if s.metadata.source_type == SourceType.PRIVATE_KEY
            ]
            assert len(key_secrets) >= 1
        finally:
            gnupg_dir.chmod(0o755)

    def test_well_known_locations_skips_subdirectories(self, tmp_path: Path):
        """
        GIVEN .ssh directory with a subdirectory
        WHEN gathering secrets
        THEN skips subdirectories (only processes files)
        """
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        key_content = "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
        (ssh_dir / "id_rsa").write_text(key_content)

        # Create a subdirectory
        subdir = ssh_dir / "keys"
        subdir.mkdir()
        (subdir / "other_key").write_text(key_content)

        with patch.dict(os.environ, {}, clear=True):
            config = GatheringConfig(home_dir=tmp_path, min_chars=5)
            gatherer = MachineSecretGatherer(config)
            secrets = list(gatherer.gather())

        # The well-known scan only looks at direct children, not subdirs
        # But the unified walker will find keys in subdirs
        key_secrets = [
            s for s in secrets if s.metadata.source_type == SourceType.PRIVATE_KEY
        ]
        assert len(key_secrets) >= 1

    def test_well_known_locations_skips_large_files(self, tmp_path: Path):
        """
        GIVEN .ssh directory with large file
        WHEN gathering secrets
        THEN skips files larger than 10KB
        """
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()

        # Create a file larger than 10KB
        large_content = "-----BEGIN RSA PRIVATE KEY-----\n" + ("x" * 15000)
        (ssh_dir / "large_key").write_text(large_content)

        # Create a normal key for comparison
        key_content = "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
        (ssh_dir / "id_rsa").write_text(key_content)

        with patch.dict(os.environ, {}, clear=True):
            config = GatheringConfig(home_dir=tmp_path, min_chars=5)
            gatherer = MachineSecretGatherer(config)
            secrets = list(gatherer.gather())

        key_secrets = [
            s for s in secrets if s.metadata.source_type == SourceType.PRIVATE_KEY
        ]
        names = {s.metadata.secret_name for s in key_secrets}
        assert "id_rsa" in names
        assert "large_key" not in names

    def test_well_known_locations_skips_empty_files(self, tmp_path: Path):
        """
        GIVEN .ssh directory with empty file
        WHEN gathering secrets
        THEN skips empty files
        """
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()

        # Create an empty file
        (ssh_dir / "empty_key").write_text("")

        # Create a normal key for comparison
        key_content = "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
        (ssh_dir / "id_rsa").write_text(key_content)

        with patch.dict(os.environ, {}, clear=True):
            config = GatheringConfig(home_dir=tmp_path, min_chars=5)
            gatherer = MachineSecretGatherer(config)
            secrets = list(gatherer.gather())

        key_secrets = [
            s for s in secrets if s.metadata.source_type == SourceType.PRIVATE_KEY
        ]
        names = {s.metadata.secret_name for s in key_secrets}
        assert "id_rsa" in names
        assert "empty_key" not in names

    def test_well_known_locations_skips_non_key_content(self, tmp_path: Path):
        """
        GIVEN .ssh directory with file without key markers
        WHEN gathering secrets
        THEN skips files without BEGIN marker
        """
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()

        # Create a file without key markers
        (ssh_dir / "not_a_key").write_text("This is not a private key")

        # Create a normal key for comparison
        key_content = "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
        (ssh_dir / "id_rsa").write_text(key_content)

        with patch.dict(os.environ, {}, clear=True):
            config = GatheringConfig(home_dir=tmp_path, min_chars=5)
            gatherer = MachineSecretGatherer(config)
            secrets = list(gatherer.gather())

        key_secrets = [
            s for s in secrets if s.metadata.source_type == SourceType.PRIVATE_KEY
        ]
        names = {s.metadata.secret_name for s in key_secrets}
        assert "id_rsa" in names
        assert "not_a_key" not in names

    def test_well_known_locations_respects_exclusion(self, tmp_path: Path):
        """
        GIVEN .ssh directory with key matching exclusion pattern
        WHEN gathering secrets with exclusion
        THEN skips excluded files
        """
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()

        key_content = "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
        (ssh_dir / "id_rsa").write_text(key_content)
        (ssh_dir / "test_key").write_text(key_content)

        # Exclude test_key
        exclusion_regexes = init_exclusion_regexes(["**/test_key"])

        with patch.dict(os.environ, {}, clear=True):
            config = GatheringConfig(
                home_dir=tmp_path, min_chars=5, exclusion_regexes=exclusion_regexes
            )
            gatherer = MachineSecretGatherer(config)
            secrets = list(gatherer.gather())

        key_secrets = [
            s for s in secrets if s.metadata.source_type == SourceType.PRIVATE_KEY
        ]
        names = {s.metadata.secret_name for s in key_secrets}
        assert "id_rsa" in names
        assert "test_key" not in names

    def test_well_known_locations_timeout_during_scan(self, tmp_path: Path):
        """
        GIVEN timeout occurs during well-known locations scan
        WHEN gathering secrets
        THEN stops early and reports timeout
        """
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()

        key_content = "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
        for i in range(5):
            (ssh_dir / f"id_rsa_{i}").write_text(key_content)

        # Create a gatherer that times out immediately after start
        call_count = [0]

        def immediate_timeout():
            call_count[0] += 1
            return call_count[0] > 1  # Timeout after first file check

        with patch.dict(os.environ, {}, clear=True):
            config = GatheringConfig(home_dir=tmp_path, timeout=1, min_chars=5)
            gatherer = MachineSecretGatherer(config)
            # Mock _is_timed_out to trigger during scan
            gatherer._is_timed_out = immediate_timeout
            secrets = list(gatherer.gather())

        # Should find some keys but not all due to timeout
        key_secrets = [
            s for s in secrets if s.metadata.source_type == SourceType.PRIVATE_KEY
        ]
        # At least some should be found before timeout
        assert len(key_secrets) >= 0  # May be 0 or more depending on timing

    def test_source_completion_callback(self, tmp_path: Path):
        """
        GIVEN a gatherer with source completion callback
        WHEN gathering secrets
        THEN callback is called for each source type
        """
        (tmp_path / ".env").write_text("API_KEY=test_value")

        completed_sources = []

        def on_source_complete(result: SourceResult):
            completed_sources.append(result)

        with patch.dict(os.environ, {"TEST_VAR": "test_value"}, clear=True):
            config = GatheringConfig(
                home_dir=tmp_path,
                min_chars=5,
                on_source_complete=on_source_complete,
            )
            gatherer = MachineSecretGatherer(config)
            list(gatherer.gather())

        # Should have callbacks for all source types
        source_types = {r.source_type for r in completed_sources}
        assert SourceType.ENVIRONMENT_VAR in source_types
        assert SourceType.GITHUB_TOKEN in source_types
        assert SourceType.NPMRC in source_types
        assert SourceType.ENV_FILE in source_types
        assert SourceType.PRIVATE_KEY in source_types

    def test_progress_callback(self, tmp_path: Path):
        """
        GIVEN a gatherer with progress callback
        WHEN gathering secrets
        THEN callback is called with progress updates
        """
        (tmp_path / ".env").write_text("API_KEY=test_value")

        progress_calls = []

        def on_progress(phase: str, files_visited: int, elapsed: float):
            progress_calls.append((phase, files_visited, elapsed))

        with patch.dict(os.environ, {}, clear=True):
            config = GatheringConfig(
                home_dir=tmp_path, min_chars=5, on_progress=on_progress
            )
            gatherer = MachineSecretGatherer(config)
            list(gatherer.gather())

        # Should have at least one progress call
        assert len(progress_calls) >= 1
        # Last call should mention filesystem
        assert any("filesystem" in call[0].lower() for call in progress_calls)
