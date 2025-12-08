"""
Tests for Helm registry config source.
"""

import base64
import json
from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.helm_config import HelmConfigSource


class TestHelmConfigSource:
    """Tests for HelmConfigSource."""

    def test_source_type(self):
        """
        GIVEN a HelmConfigSource
        WHEN accessing source_type
        THEN it returns HELM_CONFIG
        """
        source = HelmConfigSource()
        assert source.source_type == SourceType.HELM_CONFIG

    def test_gather_with_base64_auth(self, tmp_path: Path):
        """
        GIVEN a Helm config with base64-encoded auth
        WHEN gathering secrets
        THEN yields the decoded password
        """
        helm_dir = tmp_path / ".config" / "helm" / "registry"
        helm_dir.mkdir(parents=True)
        # username:password in base64
        auth_value = base64.b64encode(b"admin:secretpassword").decode()
        config_content = {"auths": {"registry.example.com": {"auth": auth_value}}}
        (helm_dir / "config.json").write_text(json.dumps(config_content))

        source = HelmConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "secretpassword"
        assert secrets[0].metadata.source_type == SourceType.HELM_CONFIG
        assert "registry.example.com" in secrets[0].metadata.secret_name

    def test_gather_with_multiple_registries(self, tmp_path: Path):
        """
        GIVEN a Helm config with multiple registries
        WHEN gathering secrets
        THEN yields passwords for all registries
        """
        helm_dir = tmp_path / ".config" / "helm" / "registry"
        helm_dir.mkdir(parents=True)
        config_content = {
            "auths": {
                "registry1.io": {"auth": base64.b64encode(b"user1:pass1").decode()},
                "registry2.io": {"auth": base64.b64encode(b"user2:pass2").decode()},
            }
        }
        (helm_dir / "config.json").write_text(json.dumps(config_content))

        source = HelmConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 2
        values = {s.value for s in secrets}
        assert "pass1" in values
        assert "pass2" in values

    def test_gather_with_raw_auth_fallback(self, tmp_path: Path):
        """
        GIVEN a Helm config with non-base64 auth value
        WHEN gathering secrets
        THEN yields the raw auth value
        """
        helm_dir = tmp_path / ".config" / "helm" / "registry"
        helm_dir.mkdir(parents=True)
        config_content = {"auths": {"registry.io": {"auth": "not_base64_encoded!!!"}}}
        (helm_dir / "config.json").write_text(json.dumps(config_content))

        source = HelmConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "not_base64_encoded!!!"

    def test_gather_no_config_file(self, tmp_path: Path):
        """
        GIVEN no Helm config file exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = HelmConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_config(self, tmp_path: Path):
        """
        GIVEN an empty Helm config
        WHEN gathering secrets
        THEN yields nothing
        """
        helm_dir = tmp_path / ".config" / "helm" / "registry"
        helm_dir.mkdir(parents=True)
        (helm_dir / "config.json").write_text("{}")

        source = HelmConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_auths(self, tmp_path: Path):
        """
        GIVEN a Helm config with empty auths
        WHEN gathering secrets
        THEN yields nothing
        """
        helm_dir = tmp_path / ".config" / "helm" / "registry"
        helm_dir.mkdir(parents=True)
        (helm_dir / "config.json").write_text('{"auths": {}}')

        source = HelmConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_invalid_json(self, tmp_path: Path):
        """
        GIVEN a Helm config with invalid JSON
        WHEN gathering secrets
        THEN yields nothing (handles gracefully)
        """
        helm_dir = tmp_path / ".config" / "helm" / "registry"
        helm_dir.mkdir(parents=True)
        (helm_dir / "config.json").write_text("not valid json {")

        source = HelmConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_invalid_auths_type(self, tmp_path: Path):
        """
        GIVEN a Helm config where auths is not a dict
        WHEN gathering secrets
        THEN yields nothing
        """
        helm_dir = tmp_path / ".config" / "helm" / "registry"
        helm_dir.mkdir(parents=True)
        (helm_dir / "config.json").write_text('{"auths": "not_a_dict"}')

        source = HelmConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_invalid_auth_data_type(self, tmp_path: Path):
        """
        GIVEN a Helm config where registry auth data is not a dict
        WHEN gathering secrets
        THEN skips that registry
        """
        helm_dir = tmp_path / ".config" / "helm" / "registry"
        helm_dir.mkdir(parents=True)
        config_content = {"auths": {"registry.io": "not_a_dict"}}
        (helm_dir / "config.json").write_text(json.dumps(config_content))

        source = HelmConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_missing_auth_value(self, tmp_path: Path):
        """
        GIVEN a Helm config where auth value is missing or empty
        WHEN gathering secrets
        THEN skips that registry
        """
        helm_dir = tmp_path / ".config" / "helm" / "registry"
        helm_dir.mkdir(parents=True)
        config_content = {
            "auths": {
                "registry1.io": {"auth": ""},  # Empty
                "registry2.io": {},  # Missing
                "registry3.io": {"auth": None},  # None
            }
        }
        (helm_dir / "config.json").write_text(json.dumps(config_content))

        source = HelmConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_base64_without_colon(self, tmp_path: Path):
        """
        GIVEN a Helm config with base64 auth that doesn't contain colon
        WHEN gathering secrets
        THEN yields the raw auth value (fallback)
        """
        helm_dir = tmp_path / ".config" / "helm" / "registry"
        helm_dir.mkdir(parents=True)
        # Valid base64 but no colon separator
        auth_value = base64.b64encode(b"just_a_token_no_colon").decode()
        config_content = {"auths": {"registry.io": {"auth": auth_value}}}
        (helm_dir / "config.json").write_text(json.dumps(config_content))

        source = HelmConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        # Should yield the raw base64 auth since decoded doesn't have colon
        assert secrets[0].value == auth_value

    def test_gather_base64_with_empty_password(self, tmp_path: Path):
        """
        GIVEN a Helm config with base64 auth where password part is empty
        WHEN gathering secrets
        THEN yields raw auth value (fallback since password is empty)
        """
        helm_dir = tmp_path / ".config" / "helm" / "registry"
        helm_dir.mkdir(parents=True)
        # username: (empty password)
        auth_value = base64.b64encode(b"username:").decode()
        config_content = {"auths": {"registry.io": {"auth": auth_value}}}
        (helm_dir / "config.json").write_text(json.dumps(config_content))

        source = HelmConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        # Empty password triggers fallback to raw auth
        assert len(secrets) == 1
        assert secrets[0].value == auth_value
