"""
Tests for environment file (.env*) matcher.
"""

from pathlib import Path

from ggshield.core.filter import init_exclusion_regexes
from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.file_matcher import EnvFileMatcher


class TestEnvFileMatcher:
    """Tests for EnvFileMatcher."""

    def test_source_type(self):
        """
        GIVEN an EnvFileMatcher
        WHEN accessing source_type
        THEN it returns ENV_FILE
        """
        matcher = EnvFileMatcher()
        assert matcher.source_type == SourceType.ENV_FILE

    def test_matches_filename_env(self):
        """
        GIVEN an EnvFileMatcher
        WHEN checking .env filename
        THEN it matches
        """
        matcher = EnvFileMatcher()
        assert matcher.matches_filename(".env") is True

    def test_matches_filename_env_local(self):
        """
        GIVEN an EnvFileMatcher
        WHEN checking .env.local filename
        THEN it matches
        """
        matcher = EnvFileMatcher()
        assert matcher.matches_filename(".env.local") is True

    def test_matches_filename_env_production(self):
        """
        GIVEN an EnvFileMatcher
        WHEN checking .env.production filename
        THEN it matches
        """
        matcher = EnvFileMatcher()
        assert matcher.matches_filename(".env.production") is True

    def test_matches_filename_ignores_example(self):
        """
        GIVEN an EnvFileMatcher
        WHEN checking .env.example filename
        THEN it does not match
        """
        matcher = EnvFileMatcher()
        assert matcher.matches_filename(".env.example") is False
        assert matcher.matches_filename(".env.EXAMPLE") is False

    def test_matches_filename_ignores_sample(self):
        """
        GIVEN an EnvFileMatcher
        WHEN checking .env.sample filename
        THEN it does not match
        """
        matcher = EnvFileMatcher()
        assert matcher.matches_filename(".env.sample") is False

    def test_matches_filename_ignores_template(self):
        """
        GIVEN an EnvFileMatcher
        WHEN checking .env.template filename
        THEN it does not match
        """
        matcher = EnvFileMatcher()
        assert matcher.matches_filename(".env.template") is False

    def test_matches_filename_non_env_file(self):
        """
        GIVEN an EnvFileMatcher
        WHEN checking non-.env filename
        THEN it does not match
        """
        matcher = EnvFileMatcher()
        assert matcher.matches_filename("config.json") is False
        assert matcher.matches_filename("readme.txt") is False
        assert matcher.matches_filename("environment.yml") is False

    def test_extract_secrets_simple_env_file(self, tmp_path: Path):
        """
        GIVEN a .env file with key=value pairs
        WHEN extracting secrets
        THEN yields secrets with correct values
        """
        env_content = """
API_KEY=my_secret_api_key
DATABASE_PASSWORD=super_secret_pass123
"""
        env_file = tmp_path / ".env"
        env_file.write_text(env_content)

        matcher = EnvFileMatcher(min_chars=5)
        secrets = list(matcher.extract_secrets(env_file, set()))

        assert len(secrets) == 2
        names = {s.metadata.secret_name for s in secrets}
        assert names == {"API_KEY", "DATABASE_PASSWORD"}

    def test_extract_secrets_removes_quotes(self, tmp_path: Path):
        """
        GIVEN a .env file with quoted values
        WHEN extracting secrets
        THEN removes quotes from values
        """
        env_content = """
SINGLE_QUOTED='single_quoted_value'
DOUBLE_QUOTED="double_quoted_value"
NO_QUOTES=no_quotes_value
"""
        env_file = tmp_path / ".env"
        env_file.write_text(env_content)

        matcher = EnvFileMatcher(min_chars=5)
        secrets = list(matcher.extract_secrets(env_file, set()))

        values = {s.value for s in secrets}
        assert "single_quoted_value" in values
        assert "double_quoted_value" in values
        assert "no_quotes_value" in values
        # Quotes should be removed
        assert "'single_quoted_value'" not in values

    def test_extract_secrets_strips_comments(self, tmp_path: Path):
        """
        GIVEN a .env file with inline comments
        WHEN extracting secrets
        THEN strips comments from values
        """
        env_content = """
SECRET=actual_value # this is a comment
"""
        env_file = tmp_path / ".env"
        env_file.write_text(env_content)

        matcher = EnvFileMatcher(min_chars=5)
        secrets = list(matcher.extract_secrets(env_file, set()))

        assert len(secrets) == 1
        assert secrets[0].value == "actual_value"

    def test_extract_secrets_respects_min_chars(self, tmp_path: Path):
        """
        GIVEN a .env file with short values
        WHEN extracting with min_chars=10
        THEN filters out short values
        """
        env_content = """
SHORT=abc
LONG_ENOUGH=this_is_long_enough
"""
        env_file = tmp_path / ".env"
        env_file.write_text(env_content)

        matcher = EnvFileMatcher(min_chars=10)
        secrets = list(matcher.extract_secrets(env_file, set()))

        names = {s.metadata.secret_name for s in secrets}
        assert "LONG_ENOUGH" in names
        assert "SHORT" not in names

    def test_extract_secrets_respects_exclusion_patterns(self, tmp_path: Path):
        """
        GIVEN a .env file matching exclusion pattern
        WHEN extracting secrets
        THEN skips it
        """
        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()
        env_file = tests_dir / ".env"
        env_file.write_text("TEST_SECRET=test_value")

        exclusion_regexes = init_exclusion_regexes(["**/tests/**/*"])

        matcher = EnvFileMatcher(min_chars=5)
        secrets = list(matcher.extract_secrets(env_file, exclusion_regexes))

        assert len(secrets) == 0

    def test_extract_secrets_no_env_file(self, tmp_path: Path):
        """
        GIVEN a nonexistent file
        WHEN extracting secrets
        THEN yields nothing without error
        """
        env_file = tmp_path / ".env"  # Does not exist

        matcher = EnvFileMatcher(min_chars=5)
        secrets = list(matcher.extract_secrets(env_file, set()))

        assert len(secrets) == 0

    def test_matches_filename_excludes_private_key_extensions(self):
        """
        GIVEN an EnvFileMatcher
        WHEN checking files that start with .env but have private key extensions
        THEN it does not match (lets PrivateKeyMatcher handle them)
        """
        matcher = EnvFileMatcher()
        # These should NOT match - let PrivateKeyMatcher handle them
        assert matcher.matches_filename(".env.pem") is False
        assert matcher.matches_filename(".env.key") is False
        assert matcher.matches_filename(".env.p12") is False
        assert matcher.matches_filename(".env.pfx") is False
        assert matcher.matches_filename(".env.gpg") is False
        assert matcher.matches_filename(".env.asc") is False
        # Case insensitive
        assert matcher.matches_filename(".env.PEM") is False
        assert matcher.matches_filename(".env.KEY") is False

    def test_matches_filename_allows_other_env_extensions(self):
        """
        GIVEN an EnvFileMatcher
        WHEN checking .env files with non-private-key extensions
        THEN it matches them
        """
        matcher = EnvFileMatcher()
        # These SHOULD match
        assert matcher.matches_filename(".env.local") is True
        assert matcher.matches_filename(".env.development") is True
        assert matcher.matches_filename(".env.production") is True
        assert matcher.matches_filename(".env.staging") is True
        assert matcher.matches_filename(".env.test") is True

    def test_allowed_dot_directories(self):
        """
        GIVEN an EnvFileMatcher
        WHEN accessing allowed_dot_directories
        THEN it returns expected directories
        """
        matcher = EnvFileMatcher()
        allowed = matcher.allowed_dot_directories

        assert ".env" in allowed
        assert ".aws" in allowed
        assert ".config" in allowed

    def test_extract_secrets_skips_placeholder_values(self, tmp_path: Path):
        """
        GIVEN a .env file with placeholder values
        WHEN extracting secrets
        THEN skips placeholder values and keeps real secrets
        """
        env_content = """
# Placeholder values that should be skipped
API_KEY=test
DATABASE_PASSWORD=changeme
SECRET_TOKEN=your_api_key
AUTH_KEY=placeholder
FILL_VALUE=–––––––FILL-ME–––––––––
TEMPLATE_KEY=your_secret_here

# Real secrets that should be kept
REAL_API_KEY=sk_live_abc123xyz789
REAL_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
"""
        env_file = tmp_path / ".env"
        env_file.write_text(env_content)

        matcher = EnvFileMatcher(min_chars=5)
        secrets = list(matcher.extract_secrets(env_file, set()))

        names = {s.metadata.secret_name for s in secrets}
        # Placeholders should be skipped
        assert "API_KEY" not in names
        assert "DATABASE_PASSWORD" not in names
        assert "SECRET_TOKEN" not in names
        assert "AUTH_KEY" not in names
        assert "FILL_VALUE" not in names
        assert "TEMPLATE_KEY" not in names
        # Real secrets should be kept
        assert "REAL_API_KEY" in names
        assert "REAL_TOKEN" in names

    def test_extract_secrets_skips_unresolved_variables(self, tmp_path: Path):
        """
        GIVEN a .env file with unresolved variable references
        WHEN extracting secrets
        THEN skips them (they're not real values)
        """
        env_content = """
UNRESOLVED_VAR=${SOME_OTHER_VAR}
ANOTHER_UNRESOLVED=$OTHER_VAR
REAL_SECRET=actual_secret_value_here
"""
        env_file = tmp_path / ".env"
        env_file.write_text(env_content)

        matcher = EnvFileMatcher(min_chars=5)
        secrets = list(matcher.extract_secrets(env_file, set()))

        names = {s.metadata.secret_name for s in secrets}
        # Unresolved variables should be skipped
        assert "UNRESOLVED_VAR" not in names
        assert "ANOTHER_UNRESOLVED" not in names
        # Real secret should be kept
        assert "REAL_SECRET" in names

    def test_extract_secrets_skips_non_secret_names(self, tmp_path: Path):
        """
        GIVEN a .env file with non-secret variable names
        WHEN extracting secrets
        THEN skips variables with names indicating config (not secrets)
        """
        env_content = """
# Non-secret names that should be skipped
DATABASE_URL=postgres://localhost:5432/mydb
API_HOST=api.example.com
AWS_REGION=us-east-1
METABASE_URL=https://metabase.example.com
LOG_LEVEL=debug
SNOWFLAKE_WAREHOUSE=compute_warehouse
SNOWFLAKE_ROLE=analyst_role

# Real secrets that should be kept
API_KEY=sk_live_abc123xyz789012345
SECRET_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
"""
        env_file = tmp_path / ".env"
        env_file.write_text(env_content)

        matcher = EnvFileMatcher(min_chars=5)
        secrets = list(matcher.extract_secrets(env_file, set()))

        names = {s.metadata.secret_name for s in secrets}
        # Non-secret names should be skipped
        assert "DATABASE_URL" not in names
        assert "API_HOST" not in names
        assert "AWS_REGION" not in names
        assert "METABASE_URL" not in names
        assert "LOG_LEVEL" not in names
        assert "SNOWFLAKE_WAREHOUSE" not in names
        assert "SNOWFLAKE_ROLE" not in names
        # Real secrets should be kept
        assert "API_KEY" in names
        assert "SECRET_TOKEN" in names

    def test_extract_secrets_skips_non_secret_values(self, tmp_path: Path):
        """
        GIVEN a .env file with non-secret values
        WHEN extracting secrets
        THEN skips values that look like config (URLs, IPs, paths)
        """
        env_content = """
# Non-secret values that should be skipped
SOME_URL=https://api.example.com/v1
SOME_IP=192.168.1.100
SOME_PATH=/var/log/app.log
SOME_BOOL=enabled
SOME_LEVEL=production
SOME_EMAIL=user@example.com
SOME_REGION=eu-west-2

# Real secrets that should be kept
REAL_KEY=sk_live_abc123xyz789012345
REAL_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
"""
        env_file = tmp_path / ".env"
        env_file.write_text(env_content)

        matcher = EnvFileMatcher(min_chars=5)
        secrets = list(matcher.extract_secrets(env_file, set()))

        names = {s.metadata.secret_name for s in secrets}
        # Non-secret values should be skipped
        assert "SOME_URL" not in names
        assert "SOME_IP" not in names
        assert "SOME_PATH" not in names
        assert "SOME_BOOL" not in names
        assert "SOME_LEVEL" not in names
        assert "SOME_EMAIL" not in names
        assert "SOME_REGION" not in names
        # Real secrets should be kept
        assert "REAL_KEY" in names
        assert "REAL_TOKEN" in names
