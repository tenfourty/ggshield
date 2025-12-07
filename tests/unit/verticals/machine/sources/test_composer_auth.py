"""
Tests for Composer auth.json credentials source.
"""

import json
from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.composer_auth import ComposerAuthSource


class TestComposerAuthSource:
    """Tests for ComposerAuthSource."""

    def test_source_type(self):
        """
        GIVEN a ComposerAuthSource
        WHEN accessing source_type
        THEN it returns COMPOSER_AUTH
        """
        source = ComposerAuthSource()
        assert source.source_type == SourceType.COMPOSER_AUTH

    def test_gather_github_oauth(self, tmp_path: Path):
        """
        GIVEN an auth.json with github-oauth
        WHEN gathering secrets
        THEN yields the token
        """
        composer_dir = tmp_path / ".composer"
        composer_dir.mkdir()
        auth_content = {"github-oauth": {"github.com": "ghp_xxxxxxxxxxxxxxxxxxxx"}}
        (composer_dir / "auth.json").write_text(json.dumps(auth_content))

        source = ComposerAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "ghp_xxxxxxxxxxxxxxxxxxxx"
        assert secrets[0].metadata.secret_name == "github-oauth/github.com"

    def test_gather_http_basic(self, tmp_path: Path):
        """
        GIVEN an auth.json with http-basic credentials
        WHEN gathering secrets
        THEN yields the password
        """
        composer_dir = tmp_path / ".composer"
        composer_dir.mkdir()
        auth_content = {
            "http-basic": {
                "repo.packagist.com": {
                    "username": "user",
                    "password": "secret_password_123",
                }
            }
        }
        (composer_dir / "auth.json").write_text(json.dumps(auth_content))

        source = ComposerAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "secret_password_123"
        assert "http-basic" in secrets[0].metadata.secret_name

    def test_gather_gitlab_token(self, tmp_path: Path):
        """
        GIVEN an auth.json with gitlab-token
        WHEN gathering secrets
        THEN yields the token
        """
        composer_dir = tmp_path / ".composer"
        composer_dir.mkdir()
        auth_content = {"gitlab-token": {"gitlab.com": "glpat-xxxxxxxxxxxx"}}
        (composer_dir / "auth.json").write_text(json.dumps(auth_content))

        source = ComposerAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "glpat-xxxxxxxxxxxx"

    def test_gather_bitbucket_oauth(self, tmp_path: Path):
        """
        GIVEN an auth.json with bitbucket-oauth
        WHEN gathering secrets
        THEN yields the consumer-secret
        """
        composer_dir = tmp_path / ".composer"
        composer_dir.mkdir()
        auth_content = {
            "bitbucket-oauth": {
                "bitbucket.org": {
                    "consumer-key": "key123",
                    "consumer-secret": "secret456",
                }
            }
        }
        (composer_dir / "auth.json").write_text(json.dumps(auth_content))

        source = ComposerAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "secret456"

    def test_gather_bearer_token(self, tmp_path: Path):
        """
        GIVEN an auth.json with bearer tokens
        WHEN gathering secrets
        THEN yields the tokens
        """
        composer_dir = tmp_path / ".composer"
        composer_dir.mkdir()
        auth_content = {"bearer": {"private.packagist.com": "bearer_token_value"}}
        (composer_dir / "auth.json").write_text(json.dumps(auth_content))

        source = ComposerAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "bearer_token_value"

    def test_gather_multiple_auth_types(self, tmp_path: Path):
        """
        GIVEN an auth.json with multiple auth types
        WHEN gathering secrets
        THEN yields all secrets
        """
        composer_dir = tmp_path / ".composer"
        composer_dir.mkdir()
        auth_content = {
            "github-oauth": {"github.com": "gh_token"},
            "gitlab-oauth": {"gitlab.com": "gl_token"},
            "http-basic": {"repo.example.com": {"username": "u", "password": "pass"}},
        }
        (composer_dir / "auth.json").write_text(json.dumps(auth_content))

        source = ComposerAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 3
        values = {s.value for s in secrets}
        assert "gh_token" in values
        assert "gl_token" in values
        assert "pass" in values

    def test_gather_no_auth_file(self, tmp_path: Path):
        """
        GIVEN no auth.json exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = ComposerAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_auth_file(self, tmp_path: Path):
        """
        GIVEN an empty auth.json
        WHEN gathering secrets
        THEN yields nothing
        """
        composer_dir = tmp_path / ".composer"
        composer_dir.mkdir()
        (composer_dir / "auth.json").write_text("{}")

        source = ComposerAuthSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0
