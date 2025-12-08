"""
Tests for Factory CLI authentication secret source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.factory_auth import FactoryAuthSource


class TestFactoryAuthSource:
    """Tests for FactoryAuthSource."""

    def test_source_type(self):
        """
        GIVEN a FactoryAuthSource
        WHEN accessing source_type
        THEN it returns FACTORY_AUTH
        """
        source = FactoryAuthSource()
        assert source.source_type == SourceType.FACTORY_AUTH

    def test_gather_no_factory_dir(self, tmp_path: Path):
        """
        GIVEN no .factory directory
        WHEN gathering secrets
        THEN yields nothing
        """
        source = FactoryAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())
        assert len(secrets) == 0

    def test_gather_empty_factory_dir(self, tmp_path: Path):
        """
        GIVEN empty .factory directory
        WHEN gathering secrets
        THEN yields nothing
        """
        factory_dir = tmp_path / ".factory"
        factory_dir.mkdir()

        source = FactoryAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())
        assert len(secrets) == 0

    def test_gather_access_token(self, tmp_path: Path):
        """
        GIVEN auth.json with access_token
        WHEN gathering secrets
        THEN yields the token
        """
        factory_dir = tmp_path / ".factory"
        factory_dir.mkdir()
        auth_path = factory_dir / "auth.json"
        auth_path.write_text('{"access_token": "factory_access_token_12345"}')

        source = FactoryAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "factory_access_token_12345"
        assert secrets[0].metadata.secret_name == "access_token"
        assert secrets[0].metadata.source_type == SourceType.FACTORY_AUTH

    def test_gather_refresh_token(self, tmp_path: Path):
        """
        GIVEN auth.json with refresh_token
        WHEN gathering secrets
        THEN yields the token
        """
        factory_dir = tmp_path / ".factory"
        factory_dir.mkdir()
        auth_path = factory_dir / "auth.json"
        auth_path.write_text('{"refreshToken": "factory_refresh_token_12345"}')

        source = FactoryAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "factory_refresh_token_12345"
        assert secrets[0].metadata.secret_name == "refreshToken"

    def test_gather_api_key(self, tmp_path: Path):
        """
        GIVEN auth.json with api_key
        WHEN gathering secrets
        THEN yields the key
        """
        factory_dir = tmp_path / ".factory"
        factory_dir.mkdir()
        auth_path = factory_dir / "auth.json"
        auth_path.write_text('{"apiKey": "factory_api_key_12345"}')

        source = FactoryAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "factory_api_key_12345"
        assert secrets[0].metadata.secret_name == "apiKey"

    def test_gather_jwt(self, tmp_path: Path):
        """
        GIVEN auth.json with jwt token
        WHEN gathering secrets
        THEN yields the jwt
        """
        factory_dir = tmp_path / ".factory"
        factory_dir.mkdir()
        auth_path = factory_dir / "auth.json"
        auth_path.write_text('{"jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xxxx"}')

        source = FactoryAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].metadata.secret_name == "jwt"

    def test_gather_session_token(self, tmp_path: Path):
        """
        GIVEN auth.json with session_token
        WHEN gathering secrets
        THEN yields the token
        """
        factory_dir = tmp_path / ".factory"
        factory_dir.mkdir()
        auth_path = factory_dir / "auth.json"
        auth_path.write_text('{"sessionToken": "factory_session_token_12345"}')

        source = FactoryAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].metadata.secret_name == "sessionToken"

    def test_gather_bearer_token(self, tmp_path: Path):
        """
        GIVEN auth.json with bearer_token
        WHEN gathering secrets
        THEN yields the token
        """
        factory_dir = tmp_path / ".factory"
        factory_dir.mkdir()
        auth_path = factory_dir / "auth.json"
        auth_path.write_text('{"bearerToken": "factory_bearer_token_12345"}')

        source = FactoryAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].metadata.secret_name == "bearerToken"

    def test_gather_multiple_tokens(self, tmp_path: Path):
        """
        GIVEN auth.json with multiple token types
        WHEN gathering secrets
        THEN yields all tokens
        """
        factory_dir = tmp_path / ".factory"
        factory_dir.mkdir()
        auth_path = factory_dir / "auth.json"
        auth_path.write_text(
            '{"access_token": "access_12345", "refresh_token": "refresh_12345", "api_key": "api_12345"}'
        )

        source = FactoryAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 3
        secret_names = {s.metadata.secret_name for s in secrets}
        assert secret_names == {"access_token", "refresh_token", "api_key"}

    def test_gather_ignores_short_values(self, tmp_path: Path):
        """
        GIVEN auth.json with short token value
        WHEN gathering secrets
        THEN ignores values with 5 or fewer chars
        """
        factory_dir = tmp_path / ".factory"
        factory_dir.mkdir()
        auth_path = factory_dir / "auth.json"
        auth_path.write_text('{"access_token": "short"}')

        source = FactoryAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_ignores_non_string_values(self, tmp_path: Path):
        """
        GIVEN auth.json with non-string token value
        WHEN gathering secrets
        THEN ignores non-string values
        """
        factory_dir = tmp_path / ".factory"
        factory_dir.mkdir()
        auth_path = factory_dir / "auth.json"
        auth_path.write_text('{"access_token": 12345, "api_key": null, "token": false}')

        source = FactoryAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_nested_auth_structure(self, tmp_path: Path):
        """
        GIVEN auth.json with nested auth structure
        WHEN gathering secrets
        THEN finds tokens in auth subfield
        """
        factory_dir = tmp_path / ".factory"
        factory_dir.mkdir()
        auth_path = factory_dir / "auth.json"
        auth_path.write_text('{"auth": {"token": "nested_auth_token_12345"}}')

        source = FactoryAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "nested_auth_token_12345"
        assert secrets[0].metadata.secret_name == "auth.token"

    def test_gather_nested_auth_with_multiple_fields(self, tmp_path: Path):
        """
        GIVEN auth.json with nested auth structure and multiple token fields
        WHEN gathering secrets
        THEN finds all tokens in auth subfield
        """
        factory_dir = tmp_path / ".factory"
        factory_dir.mkdir()
        auth_path = factory_dir / "auth.json"
        auth_path.write_text(
            '{"auth": {"access_token": "nested_access_12345", "api_key": "nested_api_12345"}}'
        )

        source = FactoryAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 2
        secret_names = {s.metadata.secret_name for s in secrets}
        assert "auth.access_token" in secret_names
        assert "auth.api_key" in secret_names

    def test_gather_both_root_and_nested(self, tmp_path: Path):
        """
        GIVEN auth.json with both root and nested tokens
        WHEN gathering secrets
        THEN finds all tokens
        """
        factory_dir = tmp_path / ".factory"
        factory_dir.mkdir()
        auth_path = factory_dir / "auth.json"
        auth_path.write_text(
            '{"token": "root_token_12345", "auth": {"token": "nested_token_12345"}}'
        )

        source = FactoryAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 2
        values = {s.value for s in secrets}
        assert values == {"root_token_12345", "nested_token_12345"}

    def test_gather_invalid_json(self, tmp_path: Path):
        """
        GIVEN auth.json with invalid JSON
        WHEN gathering secrets
        THEN yields nothing (handles gracefully)
        """
        factory_dir = tmp_path / ".factory"
        factory_dir.mkdir()
        auth_path = factory_dir / "auth.json"
        auth_path.write_text("not valid json {")

        source = FactoryAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_json(self, tmp_path: Path):
        """
        GIVEN auth.json with empty JSON object
        WHEN gathering secrets
        THEN yields nothing
        """
        factory_dir = tmp_path / ".factory"
        factory_dir.mkdir()
        auth_path = factory_dir / "auth.json"
        auth_path.write_text("{}")

        source = FactoryAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_non_auth_nested_dict(self, tmp_path: Path):
        """
        GIVEN auth.json with nested dict that is not 'auth'
        WHEN gathering secrets
        THEN only checks the 'auth' subfield for nested tokens
        """
        factory_dir = tmp_path / ".factory"
        factory_dir.mkdir()
        auth_path = factory_dir / "auth.json"
        auth_path.write_text('{"other": {"token": "other_nested_token_12345"}}')

        source = FactoryAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        # The 'other' nested dict is not checked, only 'auth' is
        assert len(secrets) == 0
