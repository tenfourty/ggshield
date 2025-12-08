"""
Tests for Raycast configuration secret source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.raycast_config import RaycastConfigSource


class TestRaycastConfigSource:
    """Tests for RaycastConfigSource."""

    def test_source_type(self):
        """
        GIVEN a RaycastConfigSource
        WHEN accessing source_type
        THEN it returns RAYCAST_CONFIG
        """
        source = RaycastConfigSource()
        assert source.source_type == SourceType.RAYCAST_CONFIG

    def test_gather_no_config_dir(self, tmp_path: Path):
        """
        GIVEN no .config/raycast directory
        WHEN gathering secrets
        THEN yields nothing
        """
        source = RaycastConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())
        assert len(secrets) == 0

    def test_gather_empty_config_dir(self, tmp_path: Path):
        """
        GIVEN empty .config/raycast directory
        WHEN gathering secrets
        THEN yields nothing
        """
        config_dir = tmp_path / ".config" / "raycast"
        config_dir.mkdir(parents=True)

        source = RaycastConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())
        assert len(secrets) == 0

    def test_gather_access_token(self, tmp_path: Path):
        """
        GIVEN config.json with access_token
        WHEN gathering secrets
        THEN yields the token
        """
        config_dir = tmp_path / ".config" / "raycast"
        config_dir.mkdir(parents=True)
        config_path = config_dir / "config.json"
        config_path.write_text('{"access_token": "raycast_access_token_12345"}')

        source = RaycastConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "raycast_access_token_12345"
        assert secrets[0].metadata.secret_name == "access_token"
        assert secrets[0].metadata.source_type == SourceType.RAYCAST_CONFIG

    def test_gather_refresh_token(self, tmp_path: Path):
        """
        GIVEN config.json with refresh_token
        WHEN gathering secrets
        THEN yields the token
        """
        config_dir = tmp_path / ".config" / "raycast"
        config_dir.mkdir(parents=True)
        config_path = config_dir / "config.json"
        config_path.write_text('{"refreshToken": "raycast_refresh_token_12345"}')

        source = RaycastConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "raycast_refresh_token_12345"
        assert secrets[0].metadata.secret_name == "refreshToken"

    def test_gather_api_key(self, tmp_path: Path):
        """
        GIVEN config.json with api_key
        WHEN gathering secrets
        THEN yields the key
        """
        config_dir = tmp_path / ".config" / "raycast"
        config_dir.mkdir(parents=True)
        config_path = config_dir / "config.json"
        config_path.write_text('{"apiKey": "raycast_api_key_12345"}')

        source = RaycastConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "raycast_api_key_12345"
        assert secrets[0].metadata.secret_name == "apiKey"

    def test_gather_multiple_tokens(self, tmp_path: Path):
        """
        GIVEN config.json with multiple token types
        WHEN gathering secrets
        THEN yields all tokens
        """
        config_dir = tmp_path / ".config" / "raycast"
        config_dir.mkdir(parents=True)
        config_path = config_dir / "config.json"
        config_path.write_text(
            '{"access_token": "access_12345", "refresh_token": "refresh_12345", "api_key": "api_12345"}'
        )

        source = RaycastConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 3
        secret_names = {s.metadata.secret_name for s in secrets}
        assert secret_names == {"access_token", "refresh_token", "api_key"}

    def test_gather_ignores_short_values(self, tmp_path: Path):
        """
        GIVEN config.json with short token value
        WHEN gathering secrets
        THEN ignores values with 5 or fewer chars
        """
        config_dir = tmp_path / ".config" / "raycast"
        config_dir.mkdir(parents=True)
        config_path = config_dir / "config.json"
        config_path.write_text('{"access_token": "short"}')

        source = RaycastConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_ignores_non_string_values(self, tmp_path: Path):
        """
        GIVEN config.json with non-string token value
        WHEN gathering secrets
        THEN ignores non-string values
        """
        config_dir = tmp_path / ".config" / "raycast"
        config_dir.mkdir(parents=True)
        config_path = config_dir / "config.json"
        config_path.write_text('{"access_token": 12345, "api_key": null}')

        source = RaycastConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_nested_token_field(self, tmp_path: Path):
        """
        GIVEN config.json with nested structure containing token
        WHEN gathering secrets
        THEN finds token in nested structure
        """
        config_dir = tmp_path / ".config" / "raycast"
        config_dir.mkdir(parents=True)
        config_path = config_dir / "config.json"
        config_path.write_text(
            '{"extensions": {"github": {"oauth_token": "github_token_12345"}}}'
        )

        source = RaycastConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "github_token_12345"
        assert secrets[0].metadata.secret_name == "oauth_token"

    def test_gather_nested_list_with_tokens(self, tmp_path: Path):
        """
        GIVEN config.json with list containing dicts with tokens
        WHEN gathering secrets
        THEN finds tokens in list items
        """
        config_dir = tmp_path / ".config" / "raycast"
        config_dir.mkdir(parents=True)
        config_path = config_dir / "config.json"
        config_path.write_text(
            '{"accounts": [{"api_key": "account_key_12345"}, {"api_key": "account_key_67890"}]}'
        )

        source = RaycastConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 2
        values = {s.value for s in secrets}
        assert values == {"account_key_12345", "account_key_67890"}

    def test_gather_deeply_nested(self, tmp_path: Path):
        """
        GIVEN config.json with deeply nested structure
        WHEN gathering secrets
        THEN respects max_depth limit
        """
        config_dir = tmp_path / ".config" / "raycast"
        config_dir.mkdir(parents=True)
        config_path = config_dir / "config.json"
        # Create deeply nested structure (beyond max_depth)
        config_path.write_text(
            '{"a": {"b": {"c": {"d": {"e": {"f": {"secret_token": "deep_secret_12345"}}}}}}}'
        )

        source = RaycastConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        # max_depth is 5, so this should not be found
        assert len(secrets) == 0

    def test_gather_invalid_json(self, tmp_path: Path):
        """
        GIVEN config.json with invalid JSON
        WHEN gathering secrets
        THEN yields nothing (handles gracefully)
        """
        config_dir = tmp_path / ".config" / "raycast"
        config_dir.mkdir(parents=True)
        config_path = config_dir / "config.json"
        config_path.write_text("not valid json {")

        source = RaycastConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_secret_like_keys(self, tmp_path: Path):
        """
        GIVEN config.json with keys containing 'secret', 'password', etc.
        WHEN gathering secrets
        THEN finds those values
        """
        config_dir = tmp_path / ".config" / "raycast"
        config_dir.mkdir(parents=True)
        config_path = config_dir / "config.json"
        config_path.write_text(
            '{"github_secret": "gh_secret_value", "db_password": "db_pass_12345"}'
        )

        source = RaycastConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 2
        secret_names = {s.metadata.secret_name for s in secrets}
        assert secret_names == {"github_secret", "db_password"}

    def test_gather_credential_key(self, tmp_path: Path):
        """
        GIVEN config.json with keys containing 'credential'
        WHEN gathering secrets
        THEN finds those values
        """
        config_dir = tmp_path / ".config" / "raycast"
        config_dir.mkdir(parents=True)
        config_path = config_dir / "config.json"
        config_path.write_text('{"aws_credential": "AKIAIOSFODNN7EXAMPLE"}')

        source = RaycastConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].metadata.secret_name == "aws_credential"
