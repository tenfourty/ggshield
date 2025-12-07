"""
Tests for git credentials secret source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.git_credentials import GitCredentialsSource


class TestGitCredentialsSource:
    """Tests for GitCredentialsSource."""

    def test_source_type(self):
        """
        GIVEN a GitCredentialsSource
        WHEN accessing source_type
        THEN it returns GIT_CREDENTIALS
        """
        source = GitCredentialsSource()
        assert source.source_type == SourceType.GIT_CREDENTIALS

    def test_gather_with_password(self, tmp_path: Path):
        """
        GIVEN a .git-credentials file with URL credentials
        WHEN gathering secrets
        THEN yields the password
        """
        credentials_content = "https://username:ghp_xxxxxxxxxxxxxxxxxxxx@github.com"
        (tmp_path / ".git-credentials").write_text(credentials_content)

        source = GitCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "ghp_xxxxxxxxxxxxxxxxxxxx"
        assert secrets[0].metadata.source_type == SourceType.GIT_CREDENTIALS
        assert "github.com" in secrets[0].metadata.secret_name
        assert "username" in secrets[0].metadata.secret_name

    def test_gather_multiple_credentials(self, tmp_path: Path):
        """
        GIVEN a .git-credentials file with multiple entries
        WHEN gathering secrets
        THEN yields all passwords
        """
        credentials_content = """https://user1:pass1@github.com
https://user2:pass2@gitlab.com
https://user3:pass3@bitbucket.org"""
        (tmp_path / ".git-credentials").write_text(credentials_content)

        source = GitCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 3
        values = {s.value for s in secrets}
        assert "pass1" in values
        assert "pass2" in values
        assert "pass3" in values

    def test_gather_ignores_no_password(self, tmp_path: Path):
        """
        GIVEN a .git-credentials file with URL without password
        WHEN gathering secrets
        THEN ignores that entry
        """
        credentials_content = "https://username@github.com"
        (tmp_path / ".git-credentials").write_text(credentials_content)

        source = GitCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_ignores_comments(self, tmp_path: Path):
        """
        GIVEN a .git-credentials file with comment lines
        WHEN gathering secrets
        THEN ignores comments
        """
        credentials_content = """# This is a comment
https://user:password@github.com
# Another comment"""
        (tmp_path / ".git-credentials").write_text(credentials_content)

        source = GitCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "password"

    def test_gather_no_credentials_file(self, tmp_path: Path):
        """
        GIVEN no .git-credentials file exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = GitCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_credentials(self, tmp_path: Path):
        """
        GIVEN an empty .git-credentials file
        WHEN gathering secrets
        THEN yields nothing
        """
        (tmp_path / ".git-credentials").write_text("")

        source = GitCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0
