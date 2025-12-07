"""
Tests for CircleCI CLI config source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.circleci_config import CircleCIConfigSource


class TestCircleCIConfigSource:
    """Tests for CircleCIConfigSource."""

    def test_source_type(self):
        """
        GIVEN a CircleCIConfigSource
        WHEN accessing source_type
        THEN it returns CIRCLECI_CONFIG
        """
        source = CircleCIConfigSource()
        assert source.source_type == SourceType.CIRCLECI_CONFIG

    def test_gather_with_token(self, tmp_path: Path):
        """
        GIVEN a CircleCI cli.yml with token
        WHEN gathering secrets
        THEN yields the token
        """
        circleci_dir = tmp_path / ".circleci"
        circleci_dir.mkdir()
        config_content = """host: https://circleci.com
endpoint: graphql-unstable
token: cc_xxxxxxxxxxxxxxxxxxxx
"""
        (circleci_dir / "cli.yml").write_text(config_content)

        source = CircleCIConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "cc_xxxxxxxxxxxxxxxxxxxx"
        assert secrets[0].metadata.source_type == SourceType.CIRCLECI_CONFIG
        assert secrets[0].metadata.secret_name == "token"

    def test_gather_with_quoted_token(self, tmp_path: Path):
        """
        GIVEN a CircleCI cli.yml with quoted token
        WHEN gathering secrets
        THEN yields the unquoted token
        """
        circleci_dir = tmp_path / ".circleci"
        circleci_dir.mkdir()
        config_content = """host: https://circleci.com
token: "quoted_token_123"
"""
        (circleci_dir / "cli.yml").write_text(config_content)

        source = CircleCIConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "quoted_token_123"

    def test_gather_with_single_quoted_token(self, tmp_path: Path):
        """
        GIVEN a CircleCI cli.yml with single-quoted token
        WHEN gathering secrets
        THEN yields the unquoted token
        """
        circleci_dir = tmp_path / ".circleci"
        circleci_dir.mkdir()
        config_content = """host: https://circleci.com
token: 'single_quoted_token'
"""
        (circleci_dir / "cli.yml").write_text(config_content)

        source = CircleCIConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "single_quoted_token"

    def test_gather_no_config_file(self, tmp_path: Path):
        """
        GIVEN no CircleCI cli.yml exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = CircleCIConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_config_without_token(self, tmp_path: Path):
        """
        GIVEN a CircleCI cli.yml without token
        WHEN gathering secrets
        THEN yields nothing
        """
        circleci_dir = tmp_path / ".circleci"
        circleci_dir.mkdir()
        config_content = """host: https://circleci.com
endpoint: graphql-unstable
"""
        (circleci_dir / "cli.yml").write_text(config_content)

        source = CircleCIConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_config(self, tmp_path: Path):
        """
        GIVEN an empty CircleCI cli.yml
        WHEN gathering secrets
        THEN yields nothing
        """
        circleci_dir = tmp_path / ".circleci"
        circleci_dir.mkdir()
        (circleci_dir / "cli.yml").write_text("")

        source = CircleCIConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0
