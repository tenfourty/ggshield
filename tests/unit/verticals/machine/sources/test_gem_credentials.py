"""
Tests for RubyGems credentials secret source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.gem_credentials import GemCredentialsSource


class TestGemCredentialsSource:
    """Tests for GemCredentialsSource."""

    def test_source_type(self):
        """
        GIVEN a GemCredentialsSource
        WHEN accessing source_type
        THEN it returns GEM_CREDENTIALS
        """
        source = GemCredentialsSource()
        assert source.source_type == SourceType.GEM_CREDENTIALS

    def test_gather_with_api_key(self, tmp_path: Path):
        """
        GIVEN a gem credentials file with API key
        WHEN gathering secrets
        THEN yields the API key
        """
        gem_dir = tmp_path / ".gem"
        gem_dir.mkdir()
        credentials_content = ":rubygems_api_key: rubygems_xxxxxxxxxxxxxxxxxxxx"
        (gem_dir / "credentials").write_text(credentials_content)

        source = GemCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "rubygems_xxxxxxxxxxxxxxxxxxxx"
        assert secrets[0].metadata.source_type == SourceType.GEM_CREDENTIALS
        assert "rubygems_api_key" in secrets[0].metadata.secret_name

    def test_gather_with_multiple_keys(self, tmp_path: Path):
        """
        GIVEN a gem credentials file with multiple API keys
        WHEN gathering secrets
        THEN yields all keys
        """
        gem_dir = tmp_path / ".gem"
        gem_dir.mkdir()
        credentials_content = """:rubygems_api_key: main_key_123
:other_api_key: other_key_456
:custom_host: custom_key_789"""
        (gem_dir / "credentials").write_text(credentials_content)

        source = GemCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 3
        values = {s.value for s in secrets}
        assert "main_key_123" in values
        assert "other_key_456" in values
        assert "custom_key_789" in values

    def test_gather_without_leading_colon(self, tmp_path: Path):
        """
        GIVEN a gem credentials file without leading colons
        WHEN gathering secrets
        THEN still yields the API key
        """
        gem_dir = tmp_path / ".gem"
        gem_dir.mkdir()
        credentials_content = "rubygems_api_key: key_without_colon"
        (gem_dir / "credentials").write_text(credentials_content)

        source = GemCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "key_without_colon"

    def test_gather_ignores_comments(self, tmp_path: Path):
        """
        GIVEN a gem credentials file with comments
        WHEN gathering secrets
        THEN ignores comments
        """
        gem_dir = tmp_path / ".gem"
        gem_dir.mkdir()
        credentials_content = """# This is a comment
:rubygems_api_key: actual_key
# Another comment"""
        (gem_dir / "credentials").write_text(credentials_content)

        source = GemCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "actual_key"

    def test_gather_no_credentials_file(self, tmp_path: Path):
        """
        GIVEN no gem credentials file exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = GemCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_credentials(self, tmp_path: Path):
        """
        GIVEN an empty gem credentials file
        WHEN gathering secrets
        THEN yields nothing
        """
        gem_dir = tmp_path / ".gem"
        gem_dir.mkdir()
        (gem_dir / "credentials").write_text("")

        source = GemCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0
