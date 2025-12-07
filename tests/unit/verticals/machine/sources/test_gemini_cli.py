"""
Tests for Gemini CLI credentials secret source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.gemini_cli import GeminiCliSource


class TestGeminiCliSource:
    """Tests for GeminiCliSource."""

    def test_source_type(self):
        """
        GIVEN a GeminiCliSource
        WHEN accessing source_type
        THEN it returns GEMINI_CLI
        """
        source = GeminiCliSource()
        assert source.source_type == SourceType.GEMINI_CLI

    def test_gather_gemini_api_key(self, tmp_path: Path):
        """
        GIVEN a .env file with GEMINI_API_KEY
        WHEN gathering secrets
        THEN yields the key
        """
        gemini_dir = tmp_path / ".gemini"
        gemini_dir.mkdir()

        env_content = "GEMINI_API_KEY=AIzaSyB1234567890abcdef"
        (gemini_dir / ".env").write_text(env_content)

        source = GeminiCliSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "AIzaSyB1234567890abcdef"
        assert secrets[0].metadata.source_type == SourceType.GEMINI_CLI
        assert secrets[0].metadata.secret_name == "GEMINI_API_KEY"

    def test_gather_google_api_key(self, tmp_path: Path):
        """
        GIVEN a .env file with GOOGLE_API_KEY
        WHEN gathering secrets
        THEN yields the key
        """
        gemini_dir = tmp_path / ".gemini"
        gemini_dir.mkdir()

        env_content = "GOOGLE_API_KEY=AIzaSyC-google-key-123"
        (gemini_dir / ".env").write_text(env_content)

        source = GeminiCliSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "AIzaSyC-google-key-123"
        assert secrets[0].metadata.secret_name == "GOOGLE_API_KEY"

    def test_gather_multiple_keys(self, tmp_path: Path):
        """
        GIVEN a .env file with multiple API keys
        WHEN gathering secrets
        THEN yields all keys
        """
        gemini_dir = tmp_path / ".gemini"
        gemini_dir.mkdir()

        env_content = """GEMINI_API_KEY=gemini-key-123
GOOGLE_API_KEY=google-key-456
API_KEY=generic-key-789"""
        (gemini_dir / ".env").write_text(env_content)

        source = GeminiCliSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 3
        values = {s.value for s in secrets}
        assert "gemini-key-123" in values
        assert "google-key-456" in values
        assert "generic-key-789" in values

    def test_gather_quoted_values(self, tmp_path: Path):
        """
        GIVEN a .env file with quoted values
        WHEN gathering secrets
        THEN yields unquoted values
        """
        gemini_dir = tmp_path / ".gemini"
        gemini_dir.mkdir()

        env_content = 'GEMINI_API_KEY="quoted-key-value"'
        (gemini_dir / ".env").write_text(env_content)

        source = GeminiCliSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "quoted-key-value"

    def test_gather_no_gemini_dir(self, tmp_path: Path):
        """
        GIVEN no .gemini directory exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = GeminiCliSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_no_env_file(self, tmp_path: Path):
        """
        GIVEN .gemini directory without .env file
        WHEN gathering secrets
        THEN yields nothing
        """
        gemini_dir = tmp_path / ".gemini"
        gemini_dir.mkdir()

        source = GeminiCliSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_env_file(self, tmp_path: Path):
        """
        GIVEN an empty .env file
        WHEN gathering secrets
        THEN yields nothing
        """
        gemini_dir = tmp_path / ".gemini"
        gemini_dir.mkdir()
        (gemini_dir / ".env").write_text("")

        source = GeminiCliSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_skips_non_secret_keys(self, tmp_path: Path):
        """
        GIVEN a .env file with non-secret keys
        WHEN gathering secrets
        THEN skips non-secret keys
        """
        gemini_dir = tmp_path / ".gemini"
        gemini_dir.mkdir()

        env_content = """DEBUG=true
LOG_LEVEL=info
GEMINI_API_KEY=actual-secret-key"""
        (gemini_dir / ".env").write_text(env_content)

        source = GeminiCliSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "actual-secret-key"
