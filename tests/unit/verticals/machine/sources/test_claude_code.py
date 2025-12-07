"""
Tests for Claude Code credentials secret source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.claude_code import ClaudeCodeSource


class TestClaudeCodeSource:
    """Tests for ClaudeCodeSource."""

    def test_source_type(self):
        """
        GIVEN a ClaudeCodeSource
        WHEN accessing source_type
        THEN it returns CLAUDE_CODE
        """
        source = ClaudeCodeSource()
        assert source.source_type == SourceType.CLAUDE_CODE

    def test_gather_access_token(self, tmp_path: Path):
        """
        GIVEN a credentials.json with access_token
        WHEN gathering secrets
        THEN yields the token
        """
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()

        creds_content = '{"access_token": "sk-ant-oauth-access-token-123"}'
        (claude_dir / "credentials.json").write_text(creds_content)

        source = ClaudeCodeSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "sk-ant-oauth-access-token-123"
        assert secrets[0].metadata.source_type == SourceType.CLAUDE_CODE
        assert secrets[0].metadata.secret_name == "access_token"

    def test_gather_refresh_token(self, tmp_path: Path):
        """
        GIVEN a credentials.json with refresh_token
        WHEN gathering secrets
        THEN yields the token
        """
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()

        creds_content = '{"refresh_token": "refresh-token-456"}'
        (claude_dir / "credentials.json").write_text(creds_content)

        source = ClaudeCodeSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "refresh-token-456"
        assert secrets[0].metadata.secret_name == "refresh_token"

    def test_gather_multiple_tokens(self, tmp_path: Path):
        """
        GIVEN a credentials.json with multiple token types
        WHEN gathering secrets
        THEN yields all tokens
        """
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()

        creds_content = """{
    "access_token": "access-123",
    "refresh_token": "refresh-456",
    "id_token": "id-789"
}"""
        (claude_dir / "credentials.json").write_text(creds_content)

        source = ClaudeCodeSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 3
        values = {s.value for s in secrets}
        assert "access-123" in values
        assert "refresh-456" in values
        assert "id-789" in values

    def test_gather_api_key_from_config(self, tmp_path: Path):
        """
        GIVEN a claude.json with api_key
        WHEN gathering secrets
        THEN yields the API key
        """
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()

        config_content = '{"api_key": "sk-ant-api-key-xyz"}'
        (claude_dir / "claude.json").write_text(config_content)

        source = ClaudeCodeSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "sk-ant-api-key-xyz"
        assert secrets[0].metadata.secret_name == "api_key"

    def test_gather_both_files(self, tmp_path: Path):
        """
        GIVEN both credentials.json and claude.json with secrets
        WHEN gathering secrets
        THEN yields secrets from both
        """
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()

        (claude_dir / "credentials.json").write_text('{"access_token": "oauth-token"}')
        (claude_dir / "claude.json").write_text('{"apiKey": "api-key-123"}')

        source = ClaudeCodeSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 2
        values = {s.value for s in secrets}
        assert "oauth-token" in values
        assert "api-key-123" in values

    def test_gather_no_claude_dir(self, tmp_path: Path):
        """
        GIVEN no .claude directory exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = ClaudeCodeSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_credentials(self, tmp_path: Path):
        """
        GIVEN an empty credentials.json
        WHEN gathering secrets
        THEN yields nothing
        """
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        (claude_dir / "credentials.json").write_text("{}")

        source = ClaudeCodeSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_invalid_json(self, tmp_path: Path):
        """
        GIVEN an invalid JSON file
        WHEN gathering secrets
        THEN yields nothing
        """
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        (claude_dir / "credentials.json").write_text("not valid json")

        source = ClaudeCodeSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0
