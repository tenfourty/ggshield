"""
Tests for Travis CI config secret source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.travis_ci_config import TravisCIConfigSource


class TestTravisCIConfigSource:
    """Tests for TravisCIConfigSource."""

    def test_source_type(self):
        """
        GIVEN a TravisCIConfigSource
        WHEN accessing source_type
        THEN it returns TRAVIS_CI_CONFIG
        """
        source = TravisCIConfigSource()
        assert source.source_type == SourceType.TRAVIS_CI_CONFIG

    def test_gather_with_token(self, tmp_path: Path):
        """
        GIVEN a Travis CI config with access_token
        WHEN gathering secrets
        THEN yields the token
        """
        travis_dir = tmp_path / ".travis"
        travis_dir.mkdir()

        config_content = """last_check:
  at: 2024-01-01 00:00:00.000000000 Z
  etag: '"abc123"'
repos: {}
endpoints:
  https://api.travis-ci.com/:
    access_token: my-travis-token-123
"""
        (travis_dir / "config.yml").write_text(config_content)

        source = TravisCIConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "my-travis-token-123"
        assert secrets[0].metadata.source_type == SourceType.TRAVIS_CI_CONFIG

    def test_gather_multiple_endpoints(self, tmp_path: Path):
        """
        GIVEN a Travis CI config with multiple endpoints
        WHEN gathering secrets
        THEN yields all tokens
        """
        travis_dir = tmp_path / ".travis"
        travis_dir.mkdir()

        config_content = """endpoints:
  https://api.travis-ci.com/:
    access_token: token1
  https://api.travis-ci.org/:
    access_token: token2
"""
        (travis_dir / "config.yml").write_text(config_content)

        source = TravisCIConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 2
        values = {s.value for s in secrets}
        assert "token1" in values
        assert "token2" in values

    def test_gather_no_travis_dir(self, tmp_path: Path):
        """
        GIVEN no .travis directory exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = TravisCIConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_no_config_file(self, tmp_path: Path):
        """
        GIVEN .travis directory without config.yml
        WHEN gathering secrets
        THEN yields nothing
        """
        travis_dir = tmp_path / ".travis"
        travis_dir.mkdir()

        source = TravisCIConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_config(self, tmp_path: Path):
        """
        GIVEN an empty config.yml
        WHEN gathering secrets
        THEN yields nothing
        """
        travis_dir = tmp_path / ".travis"
        travis_dir.mkdir()
        (travis_dir / "config.yml").write_text("")

        source = TravisCIConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_no_access_token(self, tmp_path: Path):
        """
        GIVEN a config without access_token entries
        WHEN gathering secrets
        THEN yields nothing
        """
        travis_dir = tmp_path / ".travis"
        travis_dir.mkdir()

        config_content = """endpoints:
  https://api.travis-ci.com/:
    username: myuser
"""
        (travis_dir / "config.yml").write_text(config_content)

        source = TravisCIConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0
