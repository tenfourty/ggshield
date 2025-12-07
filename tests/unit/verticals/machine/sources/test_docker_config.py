"""
Tests for Docker config secret source.
"""

import base64
from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.docker_config import DockerConfigSource


class TestDockerConfigSource:
    """Tests for DockerConfigSource."""

    def test_source_type(self):
        """
        GIVEN a DockerConfigSource
        WHEN accessing source_type
        THEN it returns DOCKER_CONFIG
        """
        source = DockerConfigSource()
        assert source.source_type == SourceType.DOCKER_CONFIG

    def test_gather_with_auth(self, tmp_path: Path):
        """
        GIVEN a Docker config with auth credentials
        WHEN gathering secrets
        THEN yields the auth token
        """
        docker_dir = tmp_path / ".docker"
        docker_dir.mkdir()
        # Base64 of "username:password"
        auth_value = base64.b64encode(b"username:password").decode()
        config_content = f"""{{
    "auths": {{
        "https://index.docker.io/v1/": {{
            "auth": "{auth_value}"
        }}
    }}
}}"""
        (docker_dir / "config.json").write_text(config_content)

        source = DockerConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == auth_value
        assert secrets[0].metadata.source_type == SourceType.DOCKER_CONFIG
        assert "docker.io" in secrets[0].metadata.secret_name

    def test_gather_with_identity_token(self, tmp_path: Path):
        """
        GIVEN a Docker config with identity token
        WHEN gathering secrets
        THEN yields the identity token
        """
        docker_dir = tmp_path / ".docker"
        docker_dir.mkdir()
        config_content = """{
    "auths": {
        "ghcr.io": {
            "identitytoken": "gho_xxxxxxxxxxxxxxxxxxxx"
        }
    }
}"""
        (docker_dir / "config.json").write_text(config_content)

        source = DockerConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "gho_xxxxxxxxxxxxxxxxxxxx"
        assert "identitytoken" in secrets[0].metadata.secret_name

    def test_gather_with_multiple_registries(self, tmp_path: Path):
        """
        GIVEN a Docker config with multiple registries
        WHEN gathering secrets
        THEN yields all auth tokens
        """
        docker_dir = tmp_path / ".docker"
        docker_dir.mkdir()
        auth1 = base64.b64encode(b"user1:pass1").decode()
        auth2 = base64.b64encode(b"user2:pass2").decode()
        config_content = f"""{{
    "auths": {{
        "https://index.docker.io/v1/": {{
            "auth": "{auth1}"
        }},
        "ghcr.io": {{
            "auth": "{auth2}"
        }}
    }}
}}"""
        (docker_dir / "config.json").write_text(config_content)

        source = DockerConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 2

    def test_gather_no_config_file(self, tmp_path: Path):
        """
        GIVEN no Docker config file exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = DockerConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_auths(self, tmp_path: Path):
        """
        GIVEN a Docker config with empty auths
        WHEN gathering secrets
        THEN yields nothing
        """
        docker_dir = tmp_path / ".docker"
        docker_dir.mkdir()
        config_content = '{"auths": {}}'
        (docker_dir / "config.json").write_text(config_content)

        source = DockerConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_invalid_json(self, tmp_path: Path):
        """
        GIVEN a Docker config with invalid JSON
        WHEN gathering secrets
        THEN yields nothing (handles gracefully)
        """
        docker_dir = tmp_path / ".docker"
        docker_dir.mkdir()
        (docker_dir / "config.json").write_text("not valid json {")

        source = DockerConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0
