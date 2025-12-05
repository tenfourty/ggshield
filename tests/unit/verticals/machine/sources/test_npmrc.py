"""
Tests for npmrc secret source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.npmrc import NpmrcSource


class TestNpmrcSource:
    """Tests for NpmrcSource."""

    def test_source_type(self):
        """
        GIVEN an NpmrcSource
        WHEN accessing source_type
        THEN it returns NPMRC
        """
        source = NpmrcSource()
        assert source.source_type == SourceType.NPMRC

    def test_gather_with_auth_token(self, tmp_path: Path):
        """
        GIVEN an .npmrc file with auth token
        WHEN gathering secrets
        THEN yields the auth token
        """
        npmrc_content = """
//registry.npmjs.org/:_authToken=npm_xxxxxxxxxxxxxxxxxxxx
registry=https://registry.npmjs.org/
"""
        npmrc_path = tmp_path / ".npmrc"
        npmrc_path.write_text(npmrc_content)

        source = NpmrcSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "npm_xxxxxxxxxxxxxxxxxxxx"
        assert secrets[0].metadata.source_type == SourceType.NPMRC
        assert "_authToken" in secrets[0].metadata.secret_name

    def test_gather_with_auth_basic(self, tmp_path: Path):
        """
        GIVEN an .npmrc file with _auth (base64 encoded)
        WHEN gathering secrets
        THEN yields the auth value
        """
        npmrc_content = """
_auth=dXNlcm5hbWU6cGFzc3dvcmQ=
"""
        npmrc_path = tmp_path / ".npmrc"
        npmrc_path.write_text(npmrc_content)

        source = NpmrcSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "dXNlcm5hbWU6cGFzc3dvcmQ="

    def test_gather_with_password(self, tmp_path: Path):
        """
        GIVEN an .npmrc file with _password
        WHEN gathering secrets
        THEN yields the password
        """
        npmrc_content = """
//registry.example.com/:_password=c2VjcmV0cGFzc3dvcmQ=
"""
        npmrc_path = tmp_path / ".npmrc"
        npmrc_path.write_text(npmrc_content)

        source = NpmrcSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "c2VjcmV0cGFzc3dvcmQ="

    def test_gather_ignores_non_auth_keys(self, tmp_path: Path):
        """
        GIVEN an .npmrc file with non-auth configuration
        WHEN gathering secrets
        THEN ignores those values
        """
        npmrc_content = """
registry=https://registry.npmjs.org/
cache=/home/user/.npm
prefix=/usr/local
"""
        npmrc_path = tmp_path / ".npmrc"
        npmrc_path.write_text(npmrc_content)

        source = NpmrcSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_no_npmrc_file(self, tmp_path: Path):
        """
        GIVEN no .npmrc file exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = NpmrcSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_npmrc(self, tmp_path: Path):
        """
        GIVEN an empty .npmrc file
        WHEN gathering secrets
        THEN yields nothing
        """
        npmrc_path = tmp_path / ".npmrc"
        npmrc_path.write_text("")

        source = NpmrcSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_multiple_auth_entries(self, tmp_path: Path):
        """
        GIVEN an .npmrc file with multiple auth entries
        WHEN gathering secrets
        THEN yields all auth entries
        """
        npmrc_content = """
//registry.npmjs.org/:_authToken=npm_token_1
//private.registry.com/:_authToken=private_token_2
//another.registry.com/:_password=encoded_password
"""
        npmrc_path = tmp_path / ".npmrc"
        npmrc_path.write_text(npmrc_content)

        source = NpmrcSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 3
        values = {s.value for s in secrets}
        assert "npm_token_1" in values
        assert "private_token_2" in values
        assert "encoded_password" in values
