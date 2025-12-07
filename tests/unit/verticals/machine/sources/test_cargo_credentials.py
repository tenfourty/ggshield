"""
Tests for Cargo credentials secret source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.cargo_credentials import CargoCredentialsSource


class TestCargoCredentialsSource:
    """Tests for CargoCredentialsSource."""

    def test_source_type(self):
        """
        GIVEN a CargoCredentialsSource
        WHEN accessing source_type
        THEN it returns CARGO_CREDENTIALS
        """
        source = CargoCredentialsSource()
        assert source.source_type == SourceType.CARGO_CREDENTIALS

    def test_gather_with_registry_token(self, tmp_path: Path):
        """
        GIVEN a credentials.toml with registry token
        WHEN gathering secrets
        THEN yields the token
        """
        cargo_dir = tmp_path / ".cargo"
        cargo_dir.mkdir()
        credentials_content = """
[registry]
token = "cio_xxxxxxxxxxxxxxxxxxxx"
"""
        (cargo_dir / "credentials.toml").write_text(credentials_content)

        source = CargoCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "cio_xxxxxxxxxxxxxxxxxxxx"
        assert secrets[0].metadata.source_type == SourceType.CARGO_CREDENTIALS

    def test_gather_with_multiple_registries(self, tmp_path: Path):
        """
        GIVEN a credentials.toml with multiple registries
        WHEN gathering secrets
        THEN yields all tokens
        """
        cargo_dir = tmp_path / ".cargo"
        cargo_dir.mkdir()
        credentials_content = """
[registry]
token = "main_token"

[registries.private]
token = "private_token"

[registries.corporate]
token = "corp_token"
"""
        (cargo_dir / "credentials.toml").write_text(credentials_content)

        source = CargoCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 3
        values = {s.value for s in secrets}
        assert "main_token" in values
        assert "private_token" in values
        assert "corp_token" in values

    def test_gather_old_format_without_toml_extension(self, tmp_path: Path):
        """
        GIVEN a credentials file without .toml extension (old format)
        WHEN gathering secrets
        THEN yields the token
        """
        cargo_dir = tmp_path / ".cargo"
        cargo_dir.mkdir()
        credentials_content = """
[registry]
token = "old_format_token"
"""
        (cargo_dir / "credentials").write_text(credentials_content)

        source = CargoCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "old_format_token"

    def test_gather_prefers_toml_extension(self, tmp_path: Path):
        """
        GIVEN both credentials and credentials.toml exist
        WHEN gathering secrets
        THEN only reads credentials.toml
        """
        cargo_dir = tmp_path / ".cargo"
        cargo_dir.mkdir()
        (cargo_dir / "credentials.toml").write_text('[registry]\ntoken = "new_token"')
        (cargo_dir / "credentials").write_text('[registry]\ntoken = "old_token"')

        source = CargoCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "new_token"

    def test_gather_no_credentials_file(self, tmp_path: Path):
        """
        GIVEN no Cargo credentials file exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = CargoCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_credentials(self, tmp_path: Path):
        """
        GIVEN an empty credentials file
        WHEN gathering secrets
        THEN yields nothing
        """
        cargo_dir = tmp_path / ".cargo"
        cargo_dir.mkdir()
        (cargo_dir / "credentials.toml").write_text("")

        source = CargoCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0
