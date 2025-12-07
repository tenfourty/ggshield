"""
Tests for Azure CLI credentials source.
"""

import json
from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.azure_cli import AzureCliSource


class TestAzureCliSource:
    """Tests for AzureCliSource."""

    def test_source_type(self):
        """
        GIVEN an AzureCliSource
        WHEN accessing source_type
        THEN it returns AZURE_CLI
        """
        source = AzureCliSource()
        assert source.source_type == SourceType.AZURE_CLI

    def test_gather_from_msal_cache(self, tmp_path: Path):
        """
        GIVEN an MSAL token cache with tokens
        WHEN gathering secrets
        THEN yields the tokens
        """
        azure_dir = tmp_path / ".azure"
        azure_dir.mkdir()
        cache_content = {
            "AccessToken": {
                "account-id-1": {
                    "secret": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.access_token",
                    "credential_type": "AccessToken",
                }
            },
            "RefreshToken": {
                "account-id-2": {
                    "secret": "0.refresh_token_value_here",
                    "credential_type": "RefreshToken",
                }
            },
        }
        (azure_dir / "msal_token_cache.json").write_text(json.dumps(cache_content))

        source = AzureCliSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 2
        values = {s.value for s in secrets}
        assert "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.access_token" in values
        assert "0.refresh_token_value_here" in values
        assert all(s.metadata.source_type == SourceType.AZURE_CLI for s in secrets)

    def test_gather_from_access_tokens(self, tmp_path: Path):
        """
        GIVEN a legacy accessTokens.json file
        WHEN gathering secrets
        THEN yields the tokens
        """
        azure_dir = tmp_path / ".azure"
        azure_dir.mkdir()
        tokens_content = [
            {
                "userId": "user@example.com",
                "accessToken": "legacy_access_token_123",
                "refreshToken": "legacy_refresh_token_456",
            }
        ]
        (azure_dir / "accessTokens.json").write_text(json.dumps(tokens_content))

        source = AzureCliSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 2
        values = {s.value for s in secrets}
        assert "legacy_access_token_123" in values
        assert "legacy_refresh_token_456" in values

    def test_gather_both_files(self, tmp_path: Path):
        """
        GIVEN both MSAL cache and legacy tokens files
        WHEN gathering secrets
        THEN yields tokens from both
        """
        azure_dir = tmp_path / ".azure"
        azure_dir.mkdir()

        # MSAL cache
        cache_content = {"AccessToken": {"id": {"secret": "msal_token"}}}
        (azure_dir / "msal_token_cache.json").write_text(json.dumps(cache_content))

        # Legacy tokens
        tokens_content = [{"userId": "user", "accessToken": "legacy_token"}]
        (azure_dir / "accessTokens.json").write_text(json.dumps(tokens_content))

        source = AzureCliSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 2
        values = {s.value for s in secrets}
        assert "msal_token" in values
        assert "legacy_token" in values

    def test_gather_no_azure_dir(self, tmp_path: Path):
        """
        GIVEN no .azure directory exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = AzureCliSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_msal_cache(self, tmp_path: Path):
        """
        GIVEN an empty MSAL cache file
        WHEN gathering secrets
        THEN yields nothing
        """
        azure_dir = tmp_path / ".azure"
        azure_dir.mkdir()
        (azure_dir / "msal_token_cache.json").write_text("{}")

        source = AzureCliSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0
