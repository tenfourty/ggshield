"""
Composer (PHP) authentication credentials source.

Scans ~/.composer/auth.json for package registry tokens.
"""

import json
from pathlib import Path
from typing import Iterator, Optional

from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)
from ggshield.verticals.machine.sources.base import SecretSource


class ComposerAuthSource(SecretSource):
    """Collects secrets from Composer auth.json."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.COMPOSER_AUTH

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from Composer auth.json.

        The file contains various auth types:
        - http-basic: username/password for registries
        - github-oauth: GitHub personal access tokens
        - gitlab-oauth/gitlab-token: GitLab tokens
        - bitbucket-oauth: Bitbucket app passwords
        - bearer: Bearer tokens for registries
        """
        auth_path = self._home_dir / ".composer" / "auth.json"
        if not auth_path.exists() or not auth_path.is_file():
            return

        try:
            content = auth_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        try:
            config = json.loads(content)
        except json.JSONDecodeError:
            return

        # http-basic: {"host": {"username": "...", "password": "..."}}
        http_basic = config.get("http-basic", {})
        if isinstance(http_basic, dict):
            for host, creds in http_basic.items():
                if isinstance(creds, dict):
                    password = creds.get("password")
                    if password and isinstance(password, str):
                        yield GatheredSecret(
                            value=password,
                            metadata=SecretMetadata(
                                source_type=self.source_type,
                                source_path=str(auth_path),
                                secret_name=f"http-basic/{host}/password",
                            ),
                        )

        # github-oauth: {"github.com": "token"}
        github_oauth = config.get("github-oauth", {})
        if isinstance(github_oauth, dict):
            for host, token in github_oauth.items():
                if token and isinstance(token, str):
                    yield GatheredSecret(
                        value=token,
                        metadata=SecretMetadata(
                            source_type=self.source_type,
                            source_path=str(auth_path),
                            secret_name=f"github-oauth/{host}",
                        ),
                    )

        # gitlab-oauth: {"gitlab.com": "token"}
        gitlab_oauth = config.get("gitlab-oauth", {})
        if isinstance(gitlab_oauth, dict):
            for host, token in gitlab_oauth.items():
                if token and isinstance(token, str):
                    yield GatheredSecret(
                        value=token,
                        metadata=SecretMetadata(
                            source_type=self.source_type,
                            source_path=str(auth_path),
                            secret_name=f"gitlab-oauth/{host}",
                        ),
                    )

        # gitlab-token: {"gitlab.com": "token"}
        gitlab_token = config.get("gitlab-token", {})
        if isinstance(gitlab_token, dict):
            for host, token in gitlab_token.items():
                if token and isinstance(token, str):
                    yield GatheredSecret(
                        value=token,
                        metadata=SecretMetadata(
                            source_type=self.source_type,
                            source_path=str(auth_path),
                            secret_name=f"gitlab-token/{host}",
                        ),
                    )

        # bitbucket-oauth: {"bitbucket.org": {"consumer-key": "...", "consumer-secret": "..."}}
        bitbucket_oauth = config.get("bitbucket-oauth", {})
        if isinstance(bitbucket_oauth, dict):
            for host, creds in bitbucket_oauth.items():
                if isinstance(creds, dict):
                    secret = creds.get("consumer-secret")
                    if secret and isinstance(secret, str):
                        yield GatheredSecret(
                            value=secret,
                            metadata=SecretMetadata(
                                source_type=self.source_type,
                                source_path=str(auth_path),
                                secret_name=f"bitbucket-oauth/{host}/consumer-secret",
                            ),
                        )

        # bearer: {"host": "token"}
        bearer = config.get("bearer", {})
        if isinstance(bearer, dict):
            for host, token in bearer.items():
                if token and isinstance(token, str):
                    yield GatheredSecret(
                        value=token,
                        metadata=SecretMetadata(
                            source_type=self.source_type,
                            source_path=str(auth_path),
                            secret_name=f"bearer/{host}",
                        ),
                    )
