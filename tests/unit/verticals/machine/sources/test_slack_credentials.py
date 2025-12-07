"""
Tests for Slack credentials secret source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.slack_credentials import SlackCredentialsSource


class TestSlackCredentialsSource:
    """Tests for SlackCredentialsSource."""

    def test_source_type(self):
        """
        GIVEN a SlackCredentialsSource
        WHEN accessing source_type
        THEN it returns SLACK_CREDENTIALS
        """
        source = SlackCredentialsSource()
        assert source.source_type == SourceType.SLACK_CREDENTIALS

    def test_gather_with_token(self, tmp_path: Path):
        """
        GIVEN a credentials.json with a token
        WHEN gathering secrets
        THEN yields the token
        """
        slack_dir = tmp_path / ".slack"
        slack_dir.mkdir()

        creds_content = '{"default_workspace": {"token": "xoxb-1234567890-abcdefghij"}}'
        (slack_dir / "credentials.json").write_text(creds_content)

        source = SlackCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "xoxb-1234567890-abcdefghij"
        assert secrets[0].metadata.source_type == SourceType.SLACK_CREDENTIALS

    def test_gather_multiple_workspaces(self, tmp_path: Path):
        """
        GIVEN a credentials.json with multiple workspace tokens
        WHEN gathering secrets
        THEN yields all tokens
        """
        slack_dir = tmp_path / ".slack"
        slack_dir.mkdir()

        creds_content = """{
    "workspace1": {"token": "xoxp-user-token-1"},
    "workspace2": {"token": "xoxa-app-token-2"},
    "workspace3": {"access_token": "xoxb-bot-token-3"}
}"""
        (slack_dir / "credentials.json").write_text(creds_content)

        source = SlackCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 3
        values = {s.value for s in secrets}
        assert "xoxp-user-token-1" in values
        assert "xoxa-app-token-2" in values
        assert "xoxb-bot-token-3" in values

    def test_gather_nested_tokens(self, tmp_path: Path):
        """
        GIVEN a credentials.json with nested token structure
        WHEN gathering secrets
        THEN yields tokens from nested objects
        """
        slack_dir = tmp_path / ".slack"
        slack_dir.mkdir()

        creds_content = """{
    "auth": {
        "oauth": {
            "access_token": "nested-oauth-token"
        }
    }
}"""
        (slack_dir / "credentials.json").write_text(creds_content)

        source = SlackCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "nested-oauth-token"

    def test_gather_no_slack_dir(self, tmp_path: Path):
        """
        GIVEN no .slack directory exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = SlackCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_no_credentials_file(self, tmp_path: Path):
        """
        GIVEN .slack directory without credentials.json
        WHEN gathering secrets
        THEN yields nothing
        """
        slack_dir = tmp_path / ".slack"
        slack_dir.mkdir()

        source = SlackCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_credentials(self, tmp_path: Path):
        """
        GIVEN an empty credentials.json
        WHEN gathering secrets
        THEN yields nothing
        """
        slack_dir = tmp_path / ".slack"
        slack_dir.mkdir()
        (slack_dir / "credentials.json").write_text("{}")

        source = SlackCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_invalid_json(self, tmp_path: Path):
        """
        GIVEN an invalid JSON file
        WHEN gathering secrets
        THEN yields nothing
        """
        slack_dir = tmp_path / ".slack"
        slack_dir.mkdir()
        (slack_dir / "credentials.json").write_text("not json")

        source = SlackCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0
