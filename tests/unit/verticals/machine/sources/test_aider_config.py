"""
Tests for Aider config secret source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.aider_config import AiderConfigSource


class TestAiderConfigSource:
    """Tests for AiderConfigSource."""

    def test_source_type(self):
        """
        GIVEN an AiderConfigSource
        WHEN accessing source_type
        THEN it returns AIDER_CONFIG
        """
        source = AiderConfigSource()
        assert source.source_type == SourceType.AIDER_CONFIG

    def test_gather_openai_api_key(self, tmp_path: Path):
        """
        GIVEN a .aider.conf.yml with openai-api-key
        WHEN gathering secrets
        THEN yields the key
        """
        config_content = """openai-api-key: sk-proj-1234567890abcdef
model: gpt-4
"""
        (tmp_path / ".aider.conf.yml").write_text(config_content)

        source = AiderConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "sk-proj-1234567890abcdef"
        assert secrets[0].metadata.source_type == SourceType.AIDER_CONFIG
        assert "openai-api-key" in secrets[0].metadata.secret_name

    def test_gather_anthropic_api_key(self, tmp_path: Path):
        """
        GIVEN a .aider.conf.yml with anthropic-api-key
        WHEN gathering secrets
        THEN yields the key
        """
        config_content = """anthropic-api-key: sk-ant-api-key-xyz
model: claude-3-opus
"""
        (tmp_path / ".aider.conf.yml").write_text(config_content)

        source = AiderConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "sk-ant-api-key-xyz"
        assert "anthropic-api-key" in secrets[0].metadata.secret_name

    def test_gather_multiple_api_keys(self, tmp_path: Path):
        """
        GIVEN a .aider.conf.yml with multiple API keys
        WHEN gathering secrets
        THEN yields all keys
        """
        config_content = """openai-api-key: openai-key-123
anthropic-api-key: anthropic-key-456
azure-api-key: azure-key-789
"""
        (tmp_path / ".aider.conf.yml").write_text(config_content)

        source = AiderConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 3
        values = {s.value for s in secrets}
        assert "openai-key-123" in values
        assert "anthropic-key-456" in values
        assert "azure-key-789" in values

    def test_gather_quoted_values(self, tmp_path: Path):
        """
        GIVEN a .aider.conf.yml with quoted values
        WHEN gathering secrets
        THEN yields unquoted values
        """
        config_content = 'openai-api-key: "quoted-key-value"'
        (tmp_path / ".aider.conf.yml").write_text(config_content)

        source = AiderConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "quoted-key-value"

    def test_gather_underscore_variant(self, tmp_path: Path):
        """
        GIVEN a .aider.conf.yml with underscore key names
        WHEN gathering secrets
        THEN yields the keys
        """
        config_content = """openai_api_key: underscore-key
api_key: generic-key
"""
        (tmp_path / ".aider.conf.yml").write_text(config_content)

        source = AiderConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 2
        values = {s.value for s in secrets}
        assert "underscore-key" in values
        assert "generic-key" in values

    def test_gather_no_config_file(self, tmp_path: Path):
        """
        GIVEN no .aider.conf.yml file exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = AiderConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_config(self, tmp_path: Path):
        """
        GIVEN an empty .aider.conf.yml file
        WHEN gathering secrets
        THEN yields nothing
        """
        (tmp_path / ".aider.conf.yml").write_text("")

        source = AiderConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_no_api_keys(self, tmp_path: Path):
        """
        GIVEN a .aider.conf.yml without API keys
        WHEN gathering secrets
        THEN yields nothing
        """
        config_content = """model: gpt-4
auto-commits: false
stream: true
"""
        (tmp_path / ".aider.conf.yml").write_text(config_content)

        source = AiderConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_generic_api_key_pattern(self, tmp_path: Path):
        """
        GIVEN a .aider.conf.yml with other *api*key* patterns
        WHEN gathering secrets
        THEN yields matching keys
        """
        config_content = """custom-api-key: custom-key-value
some-api-token-key: should-match
"""
        (tmp_path / ".aider.conf.yml").write_text(config_content)

        source = AiderConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        # Only custom-api-key should match (has both 'api' and 'key')
        assert len(secrets) >= 1
        values = {s.value for s in secrets}
        assert "custom-key-value" in values
