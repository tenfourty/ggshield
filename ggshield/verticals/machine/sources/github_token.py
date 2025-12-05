"""
GitHub CLI token secret source.
"""

import re
import shutil
import subprocess as sp
from typing import Iterator, Optional

from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)
from ggshield.verticals.machine.sources.base import SecretSource


# Pattern to validate GitHub tokens
GITHUB_TOKEN_PATTERN = re.compile(r"^(gho_|ghp_|ghs_|ghr_|github_pat_)")


class GitHubTokenSource(SecretSource):
    """Collects GitHub token from gh CLI if available."""

    @property
    def source_type(self) -> SourceType:
        return SourceType.GITHUB_TOKEN

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield GitHub token from gh CLI if available.

        Only yields a token if:
        - gh CLI is installed
        - User is authenticated
        - Token matches known GitHub token patterns
        """
        token = self._get_github_token()
        if token:
            yield GatheredSecret(
                value=token,
                metadata=SecretMetadata(
                    source_type=self.source_type,
                    source_path="gh auth token",
                    secret_name="github_token",
                ),
            )

    def _get_github_token(self) -> Optional[str]:
        """
        Get GitHub token from gh CLI.

        Returns None if gh is not installed, user is not authenticated,
        or token doesn't match expected patterns.
        """
        if not shutil.which("gh"):
            return None

        try:
            result = sp.run(
                ["gh", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=5,
                stdin=sp.DEVNULL,
            )
            if result.returncode == 0 and result.stdout:
                token = result.stdout.strip()
                if GITHUB_TOKEN_PATTERN.match(token):
                    return token
        except (sp.TimeoutExpired, sp.SubprocessError):
            pass
        return None
