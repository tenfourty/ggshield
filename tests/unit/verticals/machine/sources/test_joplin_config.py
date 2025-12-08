"""
Tests for Joplin configuration secret source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.joplin_config import JoplinConfigSource


class TestJoplinConfigSource:
    """Tests for JoplinConfigSource."""

    def test_source_type(self):
        """
        GIVEN a JoplinConfigSource
        WHEN accessing source_type
        THEN it returns JOPLIN_CONFIG
        """
        source = JoplinConfigSource()
        assert source.source_type == SourceType.JOPLIN_CONFIG

    def test_gather_no_config_dir(self, tmp_path: Path):
        """
        GIVEN no .config/joplin-desktop directory
        WHEN gathering secrets
        THEN yields nothing
        """
        source = JoplinConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())
        assert len(secrets) == 0

    def test_gather_empty_config_dir(self, tmp_path: Path):
        """
        GIVEN empty .config/joplin-desktop directory
        WHEN gathering secrets
        THEN yields nothing
        """
        config_dir = tmp_path / ".config" / "joplin-desktop"
        config_dir.mkdir(parents=True)

        source = JoplinConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())
        assert len(secrets) == 0

    def test_gather_joplin_cloud_password(self, tmp_path: Path):
        """
        GIVEN settings.json with Joplin Cloud password
        WHEN gathering secrets
        THEN yields the token
        """
        config_dir = tmp_path / ".config" / "joplin-desktop"
        config_dir.mkdir(parents=True)
        settings_path = config_dir / "settings.json"
        settings_path.write_text('{"sync.10.password": "joplin_cloud_token_12345"}')

        source = JoplinConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "joplin_cloud_token_12345"
        assert secrets[0].metadata.secret_name == "sync.10.password"
        assert secrets[0].metadata.source_type == SourceType.JOPLIN_CONFIG

    def test_gather_joplin_server_password(self, tmp_path: Path):
        """
        GIVEN settings.json with Joplin Server password
        WHEN gathering secrets
        THEN yields the token
        """
        config_dir = tmp_path / ".config" / "joplin-desktop"
        config_dir.mkdir(parents=True)
        settings_path = config_dir / "settings.json"
        settings_path.write_text('{"sync.5.password": "joplin_server_password_12345"}')

        source = JoplinConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "joplin_server_password_12345"
        assert secrets[0].metadata.secret_name == "sync.5.password"

    def test_gather_dropbox_oauth(self, tmp_path: Path):
        """
        GIVEN settings.json with Dropbox OAuth token
        WHEN gathering secrets
        THEN yields the token
        """
        config_dir = tmp_path / ".config" / "joplin-desktop"
        config_dir.mkdir(parents=True)
        settings_path = config_dir / "settings.json"
        settings_path.write_text('{"sync.7.auth": "dropbox_oauth_token_12345"}')

        source = JoplinConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "dropbox_oauth_token_12345"
        assert secrets[0].metadata.secret_name == "sync.7.auth"

    def test_gather_onedrive_oauth(self, tmp_path: Path):
        """
        GIVEN settings.json with OneDrive OAuth token
        WHEN gathering secrets
        THEN yields the token
        """
        config_dir = tmp_path / ".config" / "joplin-desktop"
        config_dir.mkdir(parents=True)
        settings_path = config_dir / "settings.json"
        settings_path.write_text('{"sync.3.auth": "onedrive_oauth_token_12345"}')

        source = JoplinConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "onedrive_oauth_token_12345"
        assert secrets[0].metadata.secret_name == "sync.3.auth"

    def test_gather_webdav_password(self, tmp_path: Path):
        """
        GIVEN settings.json with WebDAV password
        WHEN gathering secrets
        THEN yields the password
        """
        config_dir = tmp_path / ".config" / "joplin-desktop"
        config_dir.mkdir(parents=True)
        settings_path = config_dir / "settings.json"
        settings_path.write_text('{"sync.6.password": "webdav_password_12345"}')

        source = JoplinConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "webdav_password_12345"
        assert secrets[0].metadata.secret_name == "sync.6.password"

    def test_gather_s3_secret_key(self, tmp_path: Path):
        """
        GIVEN settings.json with S3 secret key
        WHEN gathering secrets
        THEN yields the key
        """
        config_dir = tmp_path / ".config" / "joplin-desktop"
        config_dir.mkdir(parents=True)
        settings_path = config_dir / "settings.json"
        settings_path.write_text('{"sync.8.password": "s3_secret_key_12345"}')

        source = JoplinConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "s3_secret_key_12345"
        assert secrets[0].metadata.secret_name == "sync.8.password"

    def test_gather_api_token(self, tmp_path: Path):
        """
        GIVEN settings.json with api.token
        WHEN gathering secrets
        THEN yields the token
        """
        config_dir = tmp_path / ".config" / "joplin-desktop"
        config_dir.mkdir(parents=True)
        settings_path = config_dir / "settings.json"
        settings_path.write_text('{"api.token": "joplin_api_token_12345"}')

        source = JoplinConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "joplin_api_token_12345"
        assert secrets[0].metadata.secret_name == "api.token"

    def test_gather_encryption_master_password(self, tmp_path: Path):
        """
        GIVEN settings.json with encryption master password
        WHEN gathering secrets
        THEN yields the password
        """
        config_dir = tmp_path / ".config" / "joplin-desktop"
        config_dir.mkdir(parents=True)
        settings_path = config_dir / "settings.json"
        settings_path.write_text(
            '{"encryption.masterPassword": "encryption_master_12345"}'
        )

        source = JoplinConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "encryption_master_12345"
        assert secrets[0].metadata.secret_name == "encryption.masterPassword"

    def test_gather_multiple_sync_tokens(self, tmp_path: Path):
        """
        GIVEN settings.json with multiple sync tokens
        WHEN gathering secrets
        THEN yields all tokens
        """
        config_dir = tmp_path / ".config" / "joplin-desktop"
        config_dir.mkdir(parents=True)
        settings_path = config_dir / "settings.json"
        settings_path.write_text(
            '{"sync.10.password": "cloud_token", "sync.7.auth": "dropbox_token", "sync.6.password": "webdav_pass"}'
        )

        source = JoplinConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 3
        secret_names = {s.metadata.secret_name for s in secrets}
        assert secret_names == {"sync.10.password", "sync.7.auth", "sync.6.password"}

    def test_gather_ignores_short_values(self, tmp_path: Path):
        """
        GIVEN settings.json with short token value
        WHEN gathering secrets
        THEN ignores values with 5 or fewer chars
        """
        config_dir = tmp_path / ".config" / "joplin-desktop"
        config_dir.mkdir(parents=True)
        settings_path = config_dir / "settings.json"
        settings_path.write_text('{"sync.10.password": "short"}')

        source = JoplinConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_ignores_non_string_values(self, tmp_path: Path):
        """
        GIVEN settings.json with non-string token value
        WHEN gathering secrets
        THEN ignores non-string values
        """
        config_dir = tmp_path / ".config" / "joplin-desktop"
        config_dir.mkdir(parents=True)
        settings_path = config_dir / "settings.json"
        settings_path.write_text(
            '{"sync.10.password": 12345, "sync.7.auth": null, "api.token": false}'
        )

        source = JoplinConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_generic_secret_suffixes(self, tmp_path: Path):
        """
        GIVEN settings.json with keys ending in secret suffixes
        WHEN gathering secrets
        THEN finds those values
        """
        config_dir = tmp_path / ".config" / "joplin-desktop"
        config_dir.mkdir(parents=True)
        settings_path = config_dir / "settings.json"
        settings_path.write_text(
            '{"custom.password": "custom_pass_12345", '
            '"plugin.auth": "plugin_auth_12345", "api.secret": "api_secret_12345"}'
        )

        source = JoplinConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 3
        secret_names = {s.metadata.secret_name for s in secrets}
        assert secret_names == {"custom.password", "plugin.auth", "api.secret"}

    def test_gather_token_suffix(self, tmp_path: Path):
        """
        GIVEN settings.json with key ending in .token
        WHEN gathering secrets
        THEN finds the value
        """
        config_dir = tmp_path / ".config" / "joplin-desktop"
        config_dir.mkdir(parents=True)
        settings_path = config_dir / "settings.json"
        settings_path.write_text('{"custom.token": "custom_token_12345"}')

        source = JoplinConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].metadata.secret_name == "custom.token"

    def test_gather_key_suffix(self, tmp_path: Path):
        """
        GIVEN settings.json with key ending in .key
        WHEN gathering secrets
        THEN finds the value
        """
        config_dir = tmp_path / ".config" / "joplin-desktop"
        config_dir.mkdir(parents=True)
        settings_path = config_dir / "settings.json"
        settings_path.write_text('{"encryption.key": "encryption_key_12345"}')

        source = JoplinConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].metadata.secret_name == "encryption.key"

    def test_gather_no_duplicates(self, tmp_path: Path):
        """
        GIVEN settings.json with known key that also matches suffix pattern
        WHEN gathering secrets
        THEN does not yield duplicates
        """
        config_dir = tmp_path / ".config" / "joplin-desktop"
        config_dir.mkdir(parents=True)
        settings_path = config_dir / "settings.json"
        # api.token is both a known key and ends with .token
        settings_path.write_text('{"api.token": "api_token_12345"}')

        source = JoplinConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        # Should only yield once, not twice
        assert len(secrets) == 1
        assert secrets[0].metadata.secret_name == "api.token"

    def test_gather_invalid_json(self, tmp_path: Path):
        """
        GIVEN settings.json with invalid JSON
        WHEN gathering secrets
        THEN yields nothing (handles gracefully)
        """
        config_dir = tmp_path / ".config" / "joplin-desktop"
        config_dir.mkdir(parents=True)
        settings_path = config_dir / "settings.json"
        settings_path.write_text("not valid json {")

        source = JoplinConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_json(self, tmp_path: Path):
        """
        GIVEN settings.json with empty JSON object
        WHEN gathering secrets
        THEN yields nothing
        """
        config_dir = tmp_path / ".config" / "joplin-desktop"
        config_dir.mkdir(parents=True)
        settings_path = config_dir / "settings.json"
        settings_path.write_text("{}")

        source = JoplinConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_ignores_non_secret_settings(self, tmp_path: Path):
        """
        GIVEN settings.json with non-secret settings
        WHEN gathering secrets
        THEN ignores them
        """
        config_dir = tmp_path / ".config" / "joplin-desktop"
        config_dir.mkdir(parents=True)
        settings_path = config_dir / "settings.json"
        settings_path.write_text(
            '{"locale": "en_US", "theme": "light", "fontSize": 14}'
        )

        source = JoplinConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0
