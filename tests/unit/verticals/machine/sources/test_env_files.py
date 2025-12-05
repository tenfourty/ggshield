"""
Tests for environment file (.env*) secret source.
"""

from pathlib import Path

from ggshield.core.filter import init_exclusion_regexes
from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.env_files import EnvFileSource


class TestEnvFileSource:
    """Tests for EnvFileSource."""

    def test_source_type(self):
        """
        GIVEN an EnvFileSource
        WHEN accessing source_type
        THEN it returns ENV_FILE
        """
        source = EnvFileSource()
        assert source.source_type == SourceType.ENV_FILE

    def test_gather_simple_env_file(self, tmp_path: Path):
        """
        GIVEN a .env file with key=value pairs
        WHEN gathering secrets
        THEN yields secrets with correct values
        """
        env_content = """
API_KEY=my_secret_api_key
DATABASE_URL=postgres://user:pass@localhost/db
"""
        env_file = tmp_path / ".env"
        env_file.write_text(env_content)

        source = EnvFileSource(home_dir=tmp_path, min_chars=5)
        secrets = list(source.gather())

        assert len(secrets) == 2
        names = {s.metadata.secret_name for s in secrets}
        assert names == {"API_KEY", "DATABASE_URL"}

    def test_gather_env_with_quotes(self, tmp_path: Path):
        """
        GIVEN a .env file with quoted values
        WHEN gathering secrets
        THEN removes quotes from values
        """
        env_content = """
SINGLE_QUOTED='single_quoted_value'
DOUBLE_QUOTED="double_quoted_value"
NO_QUOTES=no_quotes_value
"""
        env_file = tmp_path / ".env"
        env_file.write_text(env_content)

        source = EnvFileSource(home_dir=tmp_path, min_chars=5)
        secrets = list(source.gather())

        values = {s.value for s in secrets}
        assert "single_quoted_value" in values
        assert "double_quoted_value" in values
        assert "no_quotes_value" in values
        # Quotes should be removed
        assert "'single_quoted_value'" not in values

    def test_gather_env_with_comments(self, tmp_path: Path):
        """
        GIVEN a .env file with inline comments
        WHEN gathering secrets
        THEN strips comments from values
        """
        env_content = """
SECRET=actual_value # this is a comment
"""
        env_file = tmp_path / ".env"
        env_file.write_text(env_content)

        source = EnvFileSource(home_dir=tmp_path, min_chars=5)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "actual_value"

    def test_gather_multiple_env_files(self, tmp_path: Path):
        """
        GIVEN multiple .env files (.env, .env.local, .env.production)
        WHEN gathering secrets
        THEN yields secrets from all files
        """
        (tmp_path / ".env").write_text("BASE_SECRET=base_value")
        (tmp_path / ".env.local").write_text("LOCAL_SECRET=local_value")
        (tmp_path / ".env.production").write_text("PROD_SECRET=prod_value")

        source = EnvFileSource(home_dir=tmp_path, min_chars=5)
        secrets = list(source.gather())

        names = {s.metadata.secret_name for s in secrets}
        assert names == {"BASE_SECRET", "LOCAL_SECRET", "PROD_SECRET"}

    def test_gather_ignores_example_files(self, tmp_path: Path):
        """
        GIVEN .env.example and .env.sample files
        WHEN gathering secrets
        THEN ignores those files
        """
        (tmp_path / ".env").write_text("REAL_SECRET=real_value")
        (tmp_path / ".env.example").write_text("EXAMPLE_SECRET=example_value")
        (tmp_path / ".env.sample").write_text("SAMPLE_SECRET=sample_value")
        (tmp_path / ".env.template").write_text("TEMPLATE_SECRET=template_value")

        source = EnvFileSource(home_dir=tmp_path, min_chars=5)
        secrets = list(source.gather())

        names = {s.metadata.secret_name for s in secrets}
        assert "REAL_SECRET" in names
        assert "EXAMPLE_SECRET" not in names
        assert "SAMPLE_SECRET" not in names
        assert "TEMPLATE_SECRET" not in names

    def test_gather_nested_env_file(self, tmp_path: Path):
        """
        GIVEN a .env file in a nested directory
        WHEN gathering secrets
        THEN finds and processes it
        """
        nested_dir = tmp_path / "project" / "config"
        nested_dir.mkdir(parents=True)
        (nested_dir / ".env").write_text("NESTED_SECRET=nested_value")

        source = EnvFileSource(home_dir=tmp_path, min_chars=5)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].metadata.secret_name == "NESTED_SECRET"

    def test_gather_respects_min_chars(self, tmp_path: Path):
        """
        GIVEN a .env file with short values
        WHEN gathering with min_chars=10
        THEN filters out short values
        """
        env_content = """
SHORT=abc
LONG_ENOUGH=this_is_long_enough
"""
        (tmp_path / ".env").write_text(env_content)

        source = EnvFileSource(home_dir=tmp_path, min_chars=10)
        secrets = list(source.gather())

        names = {s.metadata.secret_name for s in secrets}
        assert "LONG_ENOUGH" in names
        assert "SHORT" not in names

    def test_gather_skips_node_modules(self, tmp_path: Path):
        """
        GIVEN a .env file inside node_modules
        WHEN gathering secrets
        THEN skips it
        """
        (tmp_path / ".env").write_text("ROOT_SECRET=root_value")
        node_modules = tmp_path / "node_modules" / "some-package"
        node_modules.mkdir(parents=True)
        (node_modules / ".env").write_text("NODE_SECRET=should_not_find")

        source = EnvFileSource(home_dir=tmp_path, min_chars=5)
        secrets = list(source.gather())

        names = {s.metadata.secret_name for s in secrets}
        assert "ROOT_SECRET" in names
        assert "NODE_SECRET" not in names

    def test_gather_respects_timeout(self, tmp_path: Path):
        """
        GIVEN a timeout callback that returns True
        WHEN gathering secrets
        THEN stops gathering
        """
        (tmp_path / ".env").write_text("SECRET=value_here")

        # Timeout immediately
        source = EnvFileSource(
            home_dir=tmp_path, min_chars=5, is_timed_out=lambda: True
        )
        secrets = list(source.gather())

        # Should stop before finding anything due to timeout
        assert len(secrets) == 0

    def test_gather_no_env_files(self, tmp_path: Path):
        """
        GIVEN a directory with no .env files
        WHEN gathering secrets
        THEN yields nothing
        """
        (tmp_path / "regular_file.txt").write_text("not an env file")

        source = EnvFileSource(home_dir=tmp_path, min_chars=5)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_respects_exclusion_patterns(self, tmp_path: Path):
        """
        GIVEN .env files in various directories
        WHEN gathering with exclusion patterns from config
        THEN skips files matching the patterns
        """
        # Create .env files in different locations
        (tmp_path / ".env").write_text("ROOT_SECRET=root_value")

        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()
        (tests_dir / ".env").write_text("TEST_SECRET=test_value")

        fixtures_dir = tmp_path / "fixtures"
        fixtures_dir.mkdir()
        (fixtures_dir / ".env").write_text("FIXTURE_SECRET=fixture_value")

        project_dir = tmp_path / "project"
        project_dir.mkdir()
        (project_dir / ".env").write_text("PROJECT_SECRET=project_value")

        # Create exclusion patterns (same format as .gitguardian.yaml ignored_paths)
        # Note: patterns end with /**/* to match files inside directories
        exclusion_regexes = init_exclusion_regexes(
            ["**/tests/**/*", "**/fixtures/**/*"]
        )

        source = EnvFileSource(
            home_dir=tmp_path, min_chars=5, exclusion_regexes=exclusion_regexes
        )
        secrets = list(source.gather())

        names = {s.metadata.secret_name for s in secrets}
        # Should find root and project secrets
        assert "ROOT_SECRET" in names
        assert "PROJECT_SECRET" in names
        # Should NOT find excluded paths
        assert "TEST_SECRET" not in names
        assert "FIXTURE_SECRET" not in names

    def test_gather_respects_specific_file_exclusion(self, tmp_path: Path):
        """
        GIVEN .env files including .env.example pattern
        WHEN gathering with exclusion pattern for .env.example
        THEN skips files matching the pattern
        """
        (tmp_path / ".env").write_text("REAL_SECRET=real_value")
        (tmp_path / ".env.backup").write_text("BACKUP_SECRET=backup_value")

        # Exclude .env.backup files via config pattern
        exclusion_regexes = init_exclusion_regexes(["**/.env.backup"])

        source = EnvFileSource(
            home_dir=tmp_path, min_chars=5, exclusion_regexes=exclusion_regexes
        )
        secrets = list(source.gather())

        names = {s.metadata.secret_name for s in secrets}
        assert "REAL_SECRET" in names
        assert "BACKUP_SECRET" not in names
