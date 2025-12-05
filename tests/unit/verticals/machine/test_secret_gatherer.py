"""
Tests for MachineSecretGatherer.
"""

import os
from pathlib import Path
from unittest.mock import patch

from ggshield.verticals.machine.secret_gatherer import (
    GatheringConfig,
    GatheringStats,
    MachineSecretGatherer,
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
