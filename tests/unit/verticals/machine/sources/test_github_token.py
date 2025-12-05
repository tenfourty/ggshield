"""
Tests for GitHub token secret source.
"""

import subprocess
from unittest.mock import patch

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.github_token import GitHubTokenSource


class TestGitHubTokenSource:
    """Tests for GitHubTokenSource."""

    def test_source_type(self):
        """
        GIVEN a GitHubTokenSource
        WHEN accessing source_type
        THEN it returns GITHUB_TOKEN
        """
        source = GitHubTokenSource()
        assert source.source_type == SourceType.GITHUB_TOKEN

    def test_gather_with_valid_token(self):
        """
        GIVEN gh CLI installed and authenticated with a valid token
        WHEN gathering secrets
        THEN yields the GitHub token
        """
        fake_token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        fake_result = subprocess.CompletedProcess(
            args=["gh", "auth", "token"],
            returncode=0,
            stdout=fake_token + "\n",
            stderr="",
        )

        with patch("shutil.which", return_value="/usr/bin/gh"):
            with patch("subprocess.run", return_value=fake_result):
                source = GitHubTokenSource()
                secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == fake_token
        assert secrets[0].metadata.source_type == SourceType.GITHUB_TOKEN
        assert secrets[0].metadata.secret_name == "github_token"

    def test_gather_with_gho_token(self):
        """
        GIVEN gh CLI with OAuth token (gho_ prefix)
        WHEN gathering secrets
        THEN yields the token
        """
        fake_token = "gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        fake_result = subprocess.CompletedProcess(
            args=["gh", "auth", "token"],
            returncode=0,
            stdout=fake_token + "\n",
            stderr="",
        )

        with patch("shutil.which", return_value="/usr/bin/gh"):
            with patch("subprocess.run", return_value=fake_result):
                source = GitHubTokenSource()
                secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == fake_token

    def test_gather_gh_not_installed(self):
        """
        GIVEN gh CLI is not installed
        WHEN gathering secrets
        THEN yields nothing
        """
        with patch("shutil.which", return_value=None):
            source = GitHubTokenSource()
            secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_gh_not_authenticated(self):
        """
        GIVEN gh CLI installed but not authenticated
        WHEN gathering secrets
        THEN yields nothing
        """
        fake_result = subprocess.CompletedProcess(
            args=["gh", "auth", "token"],
            returncode=1,
            stdout="",
            stderr="not logged in",
        )

        with patch("shutil.which", return_value="/usr/bin/gh"):
            with patch("subprocess.run", return_value=fake_result):
                source = GitHubTokenSource()
                secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_invalid_token_format(self):
        """
        GIVEN gh CLI returns a token with unexpected format
        WHEN gathering secrets
        THEN yields nothing (token doesn't match expected pattern)
        """
        fake_result = subprocess.CompletedProcess(
            args=["gh", "auth", "token"],
            returncode=0,
            stdout="invalid_token_format\n",
            stderr="",
        )

        with patch("shutil.which", return_value="/usr/bin/gh"):
            with patch("subprocess.run", return_value=fake_result):
                source = GitHubTokenSource()
                secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_subprocess_timeout(self):
        """
        GIVEN gh CLI times out
        WHEN gathering secrets
        THEN yields nothing (handles timeout gracefully)
        """
        with patch("shutil.which", return_value="/usr/bin/gh"):
            with patch(
                "subprocess.run", side_effect=subprocess.TimeoutExpired("gh", 5)
            ):
                source = GitHubTokenSource()
                secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_subprocess_error(self):
        """
        GIVEN gh CLI raises an error
        WHEN gathering secrets
        THEN yields nothing (handles error gracefully)
        """
        with patch("shutil.which", return_value="/usr/bin/gh"):
            with patch(
                "subprocess.run", side_effect=subprocess.SubprocessError("error")
            ):
                source = GitHubTokenSource()
                secrets = list(source.gather())

        assert len(secrets) == 0
