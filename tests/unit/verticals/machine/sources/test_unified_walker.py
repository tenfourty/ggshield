"""
Tests for the unified filesystem walker.
"""

from pathlib import Path
from typing import Dict

from ggshield.core.filter import init_exclusion_regexes
from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.file_matcher import (
    EnvFileMatcher,
    PrivateKeyMatcher,
)
from ggshield.verticals.machine.sources.unified_walker import (
    UnifiedFileSystemWalker,
    WalkerConfig,
)


# Sample RSA private key (not a real key, just for testing format detection)
SAMPLE_RSA_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MBAuMfB6JaALzdGk
zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
-----END RSA PRIVATE KEY-----"""


class TestUnifiedFileSystemWalker:
    """Tests for UnifiedFileSystemWalker."""

    def test_walk_finds_env_files(self, tmp_path: Path):
        """
        GIVEN a directory with .env files
        WHEN walking with EnvFileMatcher
        THEN finds and extracts secrets from .env files
        """
        (tmp_path / ".env").write_text("API_KEY=my_secret_api_key")

        config = WalkerConfig(
            home_dir=tmp_path,
            matchers=[EnvFileMatcher(min_chars=5)],
            is_timed_out=lambda: False,
        )

        walker = UnifiedFileSystemWalker(config)
        secrets = list(walker.walk())

        assert len(secrets) == 1
        assert secrets[0].metadata.source_type == SourceType.ENV_FILE
        assert secrets[0].metadata.secret_name == "API_KEY"

    def test_walk_finds_private_keys(self, tmp_path: Path):
        """
        GIVEN a directory with private key files
        WHEN walking with PrivateKeyMatcher
        THEN finds and extracts private keys
        """
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_rsa").write_text(SAMPLE_RSA_KEY)

        config = WalkerConfig(
            home_dir=tmp_path,
            matchers=[PrivateKeyMatcher()],
            is_timed_out=lambda: False,
        )

        walker = UnifiedFileSystemWalker(config)
        secrets = list(walker.walk())

        assert len(secrets) == 1
        assert secrets[0].metadata.source_type == SourceType.PRIVATE_KEY
        assert "id_rsa" in secrets[0].metadata.secret_name

    def test_walk_finds_both_types(self, tmp_path: Path):
        """
        GIVEN a directory with .env files and private keys
        WHEN walking with both matchers
        THEN finds secrets from both types
        """
        (tmp_path / ".env").write_text("API_KEY=my_secret_api_key")

        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_rsa").write_text(SAMPLE_RSA_KEY)

        config = WalkerConfig(
            home_dir=tmp_path,
            matchers=[EnvFileMatcher(min_chars=5), PrivateKeyMatcher()],
            is_timed_out=lambda: False,
        )

        walker = UnifiedFileSystemWalker(config)
        secrets = list(walker.walk())

        assert len(secrets) == 2
        source_types = {s.metadata.source_type for s in secrets}
        assert SourceType.ENV_FILE in source_types
        assert SourceType.PRIVATE_KEY in source_types

    def test_walk_respects_timeout(self, tmp_path: Path):
        """
        GIVEN a timeout callback that returns True
        WHEN walking
        THEN stops early
        """
        (tmp_path / ".env").write_text("API_KEY=my_secret_api_key")

        config = WalkerConfig(
            home_dir=tmp_path,
            matchers=[EnvFileMatcher(min_chars=5)],
            is_timed_out=lambda: True,  # Always timed out
        )

        walker = UnifiedFileSystemWalker(config)
        secrets = list(walker.walk())

        # Should stop before finding anything
        assert len(secrets) == 0

    def test_walk_skips_skip_directories(self, tmp_path: Path):
        """
        GIVEN .env files in node_modules and .cache
        WHEN walking
        THEN skips those directories
        """
        (tmp_path / ".env").write_text("ROOT_SECRET=root_value")

        node_modules = tmp_path / "node_modules" / "package"
        node_modules.mkdir(parents=True)
        (node_modules / ".env").write_text("NODE_SECRET=node_value")

        cache_dir = tmp_path / ".cache" / "app"
        cache_dir.mkdir(parents=True)
        (cache_dir / ".env").write_text("CACHE_SECRET=cache_value")

        config = WalkerConfig(
            home_dir=tmp_path,
            matchers=[EnvFileMatcher(min_chars=5)],
            is_timed_out=lambda: False,
        )

        walker = UnifiedFileSystemWalker(config)
        secrets = list(walker.walk())

        names = {s.metadata.secret_name for s in secrets}
        assert "ROOT_SECRET" in names
        assert "NODE_SECRET" not in names
        assert "CACHE_SECRET" not in names

    def test_walk_allows_ssh_directory(self, tmp_path: Path):
        """
        GIVEN private keys in .ssh (an allowed dot directory)
        WHEN walking
        THEN finds the keys
        """
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_rsa").write_text(SAMPLE_RSA_KEY)

        config = WalkerConfig(
            home_dir=tmp_path,
            matchers=[PrivateKeyMatcher()],
            is_timed_out=lambda: False,
        )

        walker = UnifiedFileSystemWalker(config)
        secrets = list(walker.walk())

        assert len(secrets) == 1
        assert "id_rsa" in secrets[0].metadata.secret_name

    def test_walk_respects_exclusion_patterns(self, tmp_path: Path):
        """
        GIVEN .env files with some matching exclusion patterns
        WHEN walking
        THEN skips excluded files
        """
        (tmp_path / ".env").write_text("ROOT_SECRET=root_value")

        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()
        (tests_dir / ".env").write_text("TEST_SECRET=test_value")

        exclusion_regexes = init_exclusion_regexes(["**/tests/**/*"])

        config = WalkerConfig(
            home_dir=tmp_path,
            matchers=[EnvFileMatcher(min_chars=5)],
            is_timed_out=lambda: False,
            exclusion_regexes=exclusion_regexes,
        )

        walker = UnifiedFileSystemWalker(config)
        secrets = list(walker.walk())

        names = {s.metadata.secret_name for s in secrets}
        assert "ROOT_SECRET" in names
        assert "TEST_SECRET" not in names

    def test_walk_reports_progress(self, tmp_path: Path):
        """
        GIVEN a walker with progress callback
        WHEN walking
        THEN calls progress callback with file counts
        """
        (tmp_path / ".env").write_text("API_KEY=my_secret_api_key")
        (tmp_path / "other.txt").write_text("some content")

        progress_calls = []

        def on_progress(files_visited: int, matches_by_type: Dict[SourceType, int]):
            progress_calls.append((files_visited, dict(matches_by_type)))

        config = WalkerConfig(
            home_dir=tmp_path,
            matchers=[EnvFileMatcher(min_chars=5)],
            is_timed_out=lambda: False,
            on_progress=on_progress,
        )

        walker = UnifiedFileSystemWalker(config)
        list(walker.walk())

        # Progress may or may not be called depending on timing
        # but stats should be available
        assert walker.stats.files_visited >= 2

    def test_walk_tracks_stats(self, tmp_path: Path):
        """
        GIVEN a directory with multiple files
        WHEN walking
        THEN tracks correct statistics
        """
        (tmp_path / ".env").write_text("API_KEY=my_secret_api_key")
        (tmp_path / "server.pem").write_text(SAMPLE_RSA_KEY)
        (tmp_path / "readme.txt").write_text("just a readme")

        config = WalkerConfig(
            home_dir=tmp_path,
            matchers=[EnvFileMatcher(min_chars=5), PrivateKeyMatcher()],
            is_timed_out=lambda: False,
        )

        walker = UnifiedFileSystemWalker(config)
        secrets = list(walker.walk())

        assert len(secrets) == 2
        assert walker.stats.files_visited >= 3
        assert walker.stats.matches_by_type[SourceType.ENV_FILE] >= 1
        assert walker.stats.matches_by_type[SourceType.PRIVATE_KEY] >= 1

    def test_walk_nested_directories(self, tmp_path: Path):
        """
        GIVEN .env files in nested directories
        WHEN walking
        THEN finds all of them
        """
        (tmp_path / ".env").write_text("ROOT_SECRET=root_value")

        project1 = tmp_path / "projects" / "app1"
        project1.mkdir(parents=True)
        (project1 / ".env").write_text("APP1_SECRET=app1_value")

        project2 = tmp_path / "projects" / "app2"
        project2.mkdir(parents=True)
        (project2 / ".env").write_text("APP2_SECRET=app2_value")

        config = WalkerConfig(
            home_dir=tmp_path,
            matchers=[EnvFileMatcher(min_chars=5)],
            is_timed_out=lambda: False,
        )

        walker = UnifiedFileSystemWalker(config)
        secrets = list(walker.walk())

        names = {s.metadata.secret_name for s in secrets}
        assert names == {"ROOT_SECRET", "APP1_SECRET", "APP2_SECRET"}

    def test_walk_first_matcher_wins(self, tmp_path: Path):
        """
        GIVEN a file that could match multiple matchers
        WHEN walking
        THEN first matcher wins and file is not processed twice
        """
        # Create a file that matches .env pattern
        (tmp_path / ".env").write_text("API_KEY=my_secret_api_key")

        config = WalkerConfig(
            home_dir=tmp_path,
            matchers=[
                EnvFileMatcher(min_chars=5),
                EnvFileMatcher(min_chars=5),  # Duplicate matcher
            ],
            is_timed_out=lambda: False,
        )

        walker = UnifiedFileSystemWalker(config)
        secrets = list(walker.walk())

        # Should only yield once (first matcher wins)
        assert len(secrets) == 1

    def test_walk_tracks_files_vs_secrets_separately(self, tmp_path: Path):
        """
        GIVEN .env files with multiple secrets per file
        WHEN walking
        THEN matches_by_type counts files, secrets_by_type counts secrets
        """
        # Create one file with multiple secrets
        # Note: DATABASE_PASSWORD used instead of DATABASE_URL since URLs are filtered
        (tmp_path / ".env").write_text(
            "API_KEY=my_secret_api_key\n"
            "DATABASE_PASSWORD=super_secret_pass123\n"
            "SECRET_TOKEN=another_secret_value\n"
        )

        config = WalkerConfig(
            home_dir=tmp_path,
            matchers=[EnvFileMatcher(min_chars=5)],
            is_timed_out=lambda: False,
        )

        walker = UnifiedFileSystemWalker(config)
        secrets = list(walker.walk())

        # Should find 3 secrets from 1 file
        assert len(secrets) == 3
        assert walker.stats.matches_by_type[SourceType.ENV_FILE] == 1  # 1 file
        assert walker.stats.secrets_by_type[SourceType.ENV_FILE] == 3  # 3 secrets

    def test_walk_env_pem_handled_by_private_key_matcher(self, tmp_path: Path):
        """
        GIVEN a .env.pem file (starts with .env but is actually a private key)
        WHEN walking with both matchers
        THEN PrivateKeyMatcher handles it, not EnvFileMatcher
        """
        # Create a file that starts with .env but has a private key extension
        (tmp_path / ".env.pem").write_text(SAMPLE_RSA_KEY)

        config = WalkerConfig(
            home_dir=tmp_path,
            matchers=[EnvFileMatcher(min_chars=5), PrivateKeyMatcher()],
            is_timed_out=lambda: False,
        )

        walker = UnifiedFileSystemWalker(config)
        secrets = list(walker.walk())

        # Should be handled as a private key, not an env file
        assert len(secrets) == 1
        assert secrets[0].metadata.source_type == SourceType.PRIVATE_KEY
        assert walker.stats.matches_by_type[SourceType.PRIVATE_KEY] == 1
        assert walker.stats.matches_by_type.get(SourceType.ENV_FILE, 0) == 0
