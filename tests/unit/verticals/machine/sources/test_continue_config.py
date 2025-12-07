"""
Tests for Continue.dev config secret source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.continue_config import ContinueConfigSource


class TestContinueConfigSource:
    """Tests for ContinueConfigSource."""

    def test_source_type(self):
        """
        GIVEN a ContinueConfigSource
        WHEN accessing source_type
        THEN it returns CONTINUE_CONFIG
        """
        source = ContinueConfigSource()
        assert source.source_type == SourceType.CONTINUE_CONFIG

    def test_gather_yaml_api_key(self, tmp_path: Path):
        """
        GIVEN a config.yaml with apiKey
        WHEN gathering secrets
        THEN yields the key
        """
        continue_dir = tmp_path / ".continue"
        continue_dir.mkdir()

        config_content = """models:
  - title: GPT-4
    provider: openai
    apiKey: sk-proj-1234567890abcdef
"""
        (continue_dir / "config.yaml").write_text(config_content)

        source = ContinueConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "sk-proj-1234567890abcdef"
        assert secrets[0].metadata.source_type == SourceType.CONTINUE_CONFIG
        assert secrets[0].metadata.secret_name == "apiKey"

    def test_gather_multiple_api_keys(self, tmp_path: Path):
        """
        GIVEN a config.yaml with multiple apiKey entries
        WHEN gathering secrets
        THEN yields all keys
        """
        continue_dir = tmp_path / ".continue"
        continue_dir.mkdir()

        config_content = """models:
  - title: GPT-4
    apiKey: openai-key-123
  - title: Claude
    apiKey: anthropic-key-456
"""
        (continue_dir / "config.yaml").write_text(config_content)

        source = ContinueConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 2
        values = {s.value for s in secrets}
        assert "openai-key-123" in values
        assert "anthropic-key-456" in values

    def test_gather_quoted_api_key(self, tmp_path: Path):
        """
        GIVEN a config.yaml with quoted apiKey
        WHEN gathering secrets
        THEN yields unquoted key
        """
        continue_dir = tmp_path / ".continue"
        continue_dir.mkdir()

        config_content = 'apiKey: "quoted-api-key-value"'
        (continue_dir / "config.yaml").write_text(config_content)

        source = ContinueConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "quoted-api-key-value"

    def test_gather_json_api_key(self, tmp_path: Path):
        """
        GIVEN a config.json with apiKey
        WHEN gathering secrets
        THEN yields the key
        """
        continue_dir = tmp_path / ".continue"
        continue_dir.mkdir()

        config_content = """{
    "models": [
        {
            "title": "GPT-4",
            "apiKey": "json-api-key-123"
        }
    ]
}"""
        (continue_dir / "config.json").write_text(config_content)

        source = ContinueConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "json-api-key-123"

    def test_gather_nested_json_api_key(self, tmp_path: Path):
        """
        GIVEN a config.json with deeply nested apiKey
        WHEN gathering secrets
        THEN yields the key with path
        """
        continue_dir = tmp_path / ".continue"
        continue_dir.mkdir()

        config_content = """{
    "providers": {
        "openai": {
            "apiKey": "nested-key-456"
        }
    }
}"""
        (continue_dir / "config.json").write_text(config_content)

        source = ContinueConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "nested-key-456"
        assert "providers" in secrets[0].metadata.secret_name

    def test_gather_both_formats(self, tmp_path: Path):
        """
        GIVEN both config.yaml and config.json with apiKeys
        WHEN gathering secrets
        THEN yields keys from both
        """
        continue_dir = tmp_path / ".continue"
        continue_dir.mkdir()

        (continue_dir / "config.yaml").write_text("apiKey: yaml-key")
        (continue_dir / "config.json").write_text('{"apiKey": "json-key"}')

        source = ContinueConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 2
        values = {s.value for s in secrets}
        assert "yaml-key" in values
        assert "json-key" in values

    def test_gather_no_continue_dir(self, tmp_path: Path):
        """
        GIVEN no .continue directory exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = ContinueConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_config(self, tmp_path: Path):
        """
        GIVEN an empty config.yaml
        WHEN gathering secrets
        THEN yields nothing
        """
        continue_dir = tmp_path / ".continue"
        continue_dir.mkdir()
        (continue_dir / "config.yaml").write_text("")

        source = ContinueConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_no_api_keys(self, tmp_path: Path):
        """
        GIVEN a config.yaml without apiKey entries
        WHEN gathering secrets
        THEN yields nothing
        """
        continue_dir = tmp_path / ".continue"
        continue_dir.mkdir()

        config_content = """models:
  - title: GPT-4
    provider: openai
"""
        (continue_dir / "config.yaml").write_text(config_content)

        source = ContinueConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_invalid_json(self, tmp_path: Path):
        """
        GIVEN an invalid JSON file
        WHEN gathering secrets
        THEN yields nothing (graceful failure)
        """
        continue_dir = tmp_path / ".continue"
        continue_dir.mkdir()
        (continue_dir / "config.json").write_text("not valid json")

        source = ContinueConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0
