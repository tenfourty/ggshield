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
