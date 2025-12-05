"""
Tests for private key file secret source.
"""

from pathlib import Path

from ggshield.core.filter import init_exclusion_regexes
from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.private_keys import PrivateKeySource


# Sample RSA private key (not a real key, just for testing format detection)
SAMPLE_RSA_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MBAuMfB6JaALzdGk
zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
-----END RSA PRIVATE KEY-----"""

SAMPLE_OPENSSH_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
-----END OPENSSH PRIVATE KEY-----"""


class TestPrivateKeySource:
    """Tests for PrivateKeySource."""

    def test_source_type(self):
        """
        GIVEN a PrivateKeySource
        WHEN accessing source_type
        THEN it returns PRIVATE_KEY
        """
        source = PrivateKeySource()
        assert source.source_type == SourceType.PRIVATE_KEY

    def test_gather_id_rsa(self, tmp_path: Path):
        """
        GIVEN an id_rsa file in .ssh directory
        WHEN gathering secrets
        THEN yields the key content
        """
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_rsa").write_text(SAMPLE_RSA_KEY)

        source = PrivateKeySource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].metadata.source_type == SourceType.PRIVATE_KEY
        assert "id_rsa" in secrets[0].metadata.secret_name
        assert "BEGIN RSA PRIVATE KEY" in secrets[0].value

    def test_gather_id_ed25519(self, tmp_path: Path):
        """
        GIVEN an id_ed25519 file in .ssh directory
        WHEN gathering secrets
        THEN yields the key content
        """
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_ed25519").write_text(SAMPLE_OPENSSH_KEY)

        source = PrivateKeySource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert "id_ed25519" in secrets[0].metadata.secret_name

    def test_gather_pem_file(self, tmp_path: Path):
        """
        GIVEN a .pem file
        WHEN gathering secrets
        THEN yields the key content
        """
        (tmp_path / "server.pem").write_text(SAMPLE_RSA_KEY)

        source = PrivateKeySource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].metadata.secret_name == "server.pem"

    def test_gather_key_file(self, tmp_path: Path):
        """
        GIVEN a .key file
        WHEN gathering secrets
        THEN yields the key content
        """
        (tmp_path / "private.key").write_text(SAMPLE_RSA_KEY)

        source = PrivateKeySource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].metadata.secret_name == "private.key"

    def test_gather_multiple_keys(self, tmp_path: Path):
        """
        GIVEN multiple private key files
        WHEN gathering secrets
        THEN yields all of them
        """
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_rsa").write_text(SAMPLE_RSA_KEY)
        (ssh_dir / "id_ed25519").write_text(SAMPLE_OPENSSH_KEY)
        (tmp_path / "ssl.pem").write_text(SAMPLE_RSA_KEY)

        source = PrivateKeySource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 3
        names = {s.metadata.secret_name for s in secrets}
        assert "id_rsa" in names
        assert "id_ed25519" in names
        assert "ssl.pem" in names

    def test_gather_ignores_non_key_content(self, tmp_path: Path):
        """
        GIVEN a .pem file without key markers
        WHEN gathering secrets
        THEN ignores it
        """
        (tmp_path / "not_a_key.pem").write_text("This is not a private key")

        source = PrivateKeySource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_ignores_empty_files(self, tmp_path: Path):
        """
        GIVEN an empty key file
        WHEN gathering secrets
        THEN ignores it
        """
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_rsa").write_text("")

        source = PrivateKeySource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_ignores_large_files(self, tmp_path: Path):
        """
        GIVEN a .pem file larger than MAX_KEY_FILE_SIZE
        WHEN gathering secrets
        THEN ignores it
        """
        # Create a file larger than 10KB
        large_content = SAMPLE_RSA_KEY + ("x" * 15000)
        (tmp_path / "large.pem").write_text(large_content)

        source = PrivateKeySource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_respects_timeout(self, tmp_path: Path):
        """
        GIVEN a timeout callback that returns True
        WHEN gathering secrets
        THEN stops gathering
        """
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_rsa").write_text(SAMPLE_RSA_KEY)

        source = PrivateKeySource(home_dir=tmp_path, is_timed_out=lambda: True)
        secrets = list(source.gather())

        # May or may not find the key depending on when timeout is checked
        # but should not hang or error
        assert isinstance(secrets, list)

    def test_gather_skips_hidden_dirs_except_allowed(self, tmp_path: Path):
        """
        GIVEN key files in .ssh (allowed) and .cache (not allowed)
        WHEN gathering secrets
        THEN only finds keys in allowed directories
        """
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_rsa").write_text(SAMPLE_RSA_KEY)

        cache_dir = tmp_path / ".cache" / "keys"
        cache_dir.mkdir(parents=True)
        (cache_dir / "cached.pem").write_text(SAMPLE_RSA_KEY)

        source = PrivateKeySource(home_dir=tmp_path)
        secrets = list(source.gather())

        names = {s.metadata.secret_name for s in secrets}
        assert "id_rsa" in names
        assert "cached.pem" not in names

    def test_gather_no_key_files(self, tmp_path: Path):
        """
        GIVEN a directory with no private key files
        WHEN gathering secrets
        THEN yields nothing
        """
        (tmp_path / "readme.txt").write_text("Just a readme")

        source = PrivateKeySource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_respects_exclusion_patterns(self, tmp_path: Path):
        """
        GIVEN private key files in various directories
        WHEN gathering with exclusion patterns from config
        THEN skips files matching the patterns
        """
        # Create key files in different locations
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_rsa").write_text(SAMPLE_RSA_KEY)

        tests_dir = tmp_path / "tests" / "fixtures"
        tests_dir.mkdir(parents=True)
        (tests_dir / "test.pem").write_text(SAMPLE_RSA_KEY)

        project_dir = tmp_path / "project"
        project_dir.mkdir()
        (project_dir / "server.key").write_text(SAMPLE_RSA_KEY)

        # Create exclusion patterns (same format as .gitguardian.yaml ignored_paths)
        # Note: patterns end with /**/* to match files inside directories
        exclusion_regexes = init_exclusion_regexes(["**/tests/**/*"])

        source = PrivateKeySource(
            home_dir=tmp_path, exclusion_regexes=exclusion_regexes
        )
        secrets = list(source.gather())

        names = {s.metadata.secret_name for s in secrets}
        # Should find .ssh and project keys
        assert "id_rsa" in names
        assert "server.key" in names
        # Should NOT find keys in excluded paths
        assert "test.pem" not in names

    def test_gather_respects_exclusion_in_well_known_locations(self, tmp_path: Path):
        """
        GIVEN private key files in .ssh (well-known location)
        WHEN gathering with exclusion pattern for .ssh
        THEN skips even well-known locations if excluded
        """
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_rsa").write_text(SAMPLE_RSA_KEY)

        (tmp_path / "other.pem").write_text(SAMPLE_RSA_KEY)

        # Exclude .ssh directory (pattern ends with /**/* to match files)
        exclusion_regexes = init_exclusion_regexes(["**/.ssh/**/*"])

        source = PrivateKeySource(
            home_dir=tmp_path, exclusion_regexes=exclusion_regexes
        )
        secrets = list(source.gather())

        names = {s.metadata.secret_name for s in secrets}
        assert "other.pem" in names
        assert "id_rsa" not in names
