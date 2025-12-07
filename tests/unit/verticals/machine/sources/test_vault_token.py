"""
Tests for HashiCorp Vault token secret source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.vault_token import VaultTokenSource


class TestVaultTokenSource:
    """Tests for VaultTokenSource."""

    def test_source_type(self):
        """
        GIVEN a VaultTokenSource
        WHEN accessing source_type
        THEN it returns VAULT_TOKEN
        """
        source = VaultTokenSource()
        assert source.source_type == SourceType.VAULT_TOKEN

    def test_gather_with_token(self, tmp_path: Path):
        """
        GIVEN a .vault-token file with a token
        WHEN gathering secrets
        THEN yields the token
        """
        token = "hvs.CAESIJvN_pwZsP...truncated"
        (tmp_path / ".vault-token").write_text(token)

        source = VaultTokenSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == token
        assert secrets[0].metadata.source_type == SourceType.VAULT_TOKEN
        assert secrets[0].metadata.secret_name == "vault-token"

    def test_gather_with_token_and_whitespace(self, tmp_path: Path):
        """
        GIVEN a .vault-token file with trailing whitespace
        WHEN gathering secrets
        THEN yields the trimmed token
        """
        (tmp_path / ".vault-token").write_text("hvs.token123\n\n")

        source = VaultTokenSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "hvs.token123"

    def test_gather_no_token_file(self, tmp_path: Path):
        """
        GIVEN no .vault-token file exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = VaultTokenSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_token_file(self, tmp_path: Path):
        """
        GIVEN an empty .vault-token file
        WHEN gathering secrets
        THEN yields nothing
        """
        (tmp_path / ".vault-token").write_text("")

        source = VaultTokenSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_whitespace_only_token_file(self, tmp_path: Path):
        """
        GIVEN a .vault-token file with only whitespace
        WHEN gathering secrets
        THEN yields nothing
        """
        (tmp_path / ".vault-token").write_text("   \n\n   ")

        source = VaultTokenSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0
