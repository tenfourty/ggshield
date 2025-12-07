"""
Tests for GitLab CLI (glab) config source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.gitlab_cli import GitLabCliSource


class TestGitLabCliSource:
    """Tests for GitLabCliSource."""

    def test_source_type(self):
        """
        GIVEN a GitLabCliSource
        WHEN accessing source_type
        THEN it returns GITLAB_CLI
        """
        source = GitLabCliSource()
        assert source.source_type == SourceType.GITLAB_CLI

    def test_gather_with_single_host(self, tmp_path: Path):
        """
        GIVEN a glab config with single host token
        WHEN gathering secrets
        THEN yields the token
        """
        glab_dir = tmp_path / ".config" / "glab-cli"
        glab_dir.mkdir(parents=True)
        config_content = """hosts:
  gitlab.com:
    token: glpat-xxxxxxxxxxxxxxxxxxxx
    git_protocol: ssh
    api_host: gitlab.com
"""
        (glab_dir / "config.yml").write_text(config_content)

        source = GitLabCliSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "glpat-xxxxxxxxxxxxxxxxxxxx"
        assert secrets[0].metadata.source_type == SourceType.GITLAB_CLI
        assert "gitlab.com/token" in secrets[0].metadata.secret_name

    def test_gather_with_multiple_hosts(self, tmp_path: Path):
        """
        GIVEN a glab config with multiple hosts
        WHEN gathering secrets
        THEN yields all tokens
        """
        glab_dir = tmp_path / ".config" / "glab-cli"
        glab_dir.mkdir(parents=True)
        config_content = """hosts:
  gitlab.com:
    token: token_gitlab_com
    git_protocol: ssh
  gitlab.example.com:
    token: token_example_com
    git_protocol: https
"""
        (glab_dir / "config.yml").write_text(config_content)

        source = GitLabCliSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 2
        values = {s.value for s in secrets}
        assert "token_gitlab_com" in values
        assert "token_example_com" in values

    def test_gather_with_quoted_token(self, tmp_path: Path):
        """
        GIVEN a glab config with quoted token
        WHEN gathering secrets
        THEN yields the unquoted token
        """
        glab_dir = tmp_path / ".config" / "glab-cli"
        glab_dir.mkdir(parents=True)
        config_content = """hosts:
  gitlab.com:
    token: "quoted_token_123"
"""
        (glab_dir / "config.yml").write_text(config_content)

        source = GitLabCliSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "quoted_token_123"

    def test_gather_no_config_file(self, tmp_path: Path):
        """
        GIVEN no glab config file exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = GitLabCliSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_config_without_hosts(self, tmp_path: Path):
        """
        GIVEN a glab config without hosts section
        WHEN gathering secrets
        THEN yields nothing
        """
        glab_dir = tmp_path / ".config" / "glab-cli"
        glab_dir.mkdir(parents=True)
        config_content = """editor: vim
protocol: ssh
"""
        (glab_dir / "config.yml").write_text(config_content)

        source = GitLabCliSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_host_without_token(self, tmp_path: Path):
        """
        GIVEN a glab config with host but no token
        WHEN gathering secrets
        THEN yields nothing
        """
        glab_dir = tmp_path / ".config" / "glab-cli"
        glab_dir.mkdir(parents=True)
        config_content = """hosts:
  gitlab.com:
    git_protocol: ssh
    api_host: gitlab.com
"""
        (glab_dir / "config.yml").write_text(config_content)

        source = GitLabCliSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_config(self, tmp_path: Path):
        """
        GIVEN an empty glab config
        WHEN gathering secrets
        THEN yields nothing
        """
        glab_dir = tmp_path / ".config" / "glab-cli"
        glab_dir.mkdir(parents=True)
        (glab_dir / "config.yml").write_text("")

        source = GitLabCliSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0
