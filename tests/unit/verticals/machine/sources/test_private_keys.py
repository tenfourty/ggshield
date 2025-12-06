"""
Tests for private key file matcher.
"""

from pathlib import Path
from typing import Set

from ggshield.core.filter import init_exclusion_regexes
from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.file_matcher import PrivateKeyMatcher


# Sample RSA private key (not a real key, just for testing format detection)
SAMPLE_RSA_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MBAuMfB6JaALzdGk
zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
-----END RSA PRIVATE KEY-----"""

SAMPLE_OPENSSH_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
-----END OPENSSH PRIVATE KEY-----"""

# Sample public certificate (NOT a private key - should be ignored)
SAMPLE_PUBLIC_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
-----END CERTIFICATE-----"""

# Combined file with both certificate and private key (should be detected)
SAMPLE_CERT_WITH_KEY = """-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MBAuMfB6JaALzdGk
-----END RSA PRIVATE KEY-----"""


class TestPrivateKeyMatcher:
    """Tests for PrivateKeyMatcher."""

    def test_source_type(self):
        """
        GIVEN a PrivateKeyMatcher
        WHEN accessing source_type
        THEN it returns PRIVATE_KEY
        """
        matcher = PrivateKeyMatcher()
        assert matcher.source_type == SourceType.PRIVATE_KEY

    def test_matches_filename_id_rsa(self):
        """
        GIVEN a PrivateKeyMatcher
        WHEN checking id_rsa filename
        THEN it matches
        """
        matcher = PrivateKeyMatcher()
        assert matcher.matches_filename("id_rsa") is True

    def test_matches_filename_id_ed25519(self):
        """
        GIVEN a PrivateKeyMatcher
        WHEN checking id_ed25519 filename
        THEN it matches
        """
        matcher = PrivateKeyMatcher()
        assert matcher.matches_filename("id_ed25519") is True

    def test_matches_filename_pem_extension(self):
        """
        GIVEN a PrivateKeyMatcher
        WHEN checking .pem file
        THEN it matches
        """
        matcher = PrivateKeyMatcher()
        assert matcher.matches_filename("server.pem") is True

    def test_matches_filename_key_extension(self):
        """
        GIVEN a PrivateKeyMatcher
        WHEN checking .key file
        THEN it matches
        """
        matcher = PrivateKeyMatcher()
        assert matcher.matches_filename("private.key") is True

    def test_matches_filename_private_key_pattern(self):
        """
        GIVEN a PrivateKeyMatcher
        WHEN checking file with 'private' and 'key' in name
        THEN it matches
        """
        matcher = PrivateKeyMatcher()
        assert matcher.matches_filename("my_private_key.txt") is True
        assert matcher.matches_filename("PRIVATE_KEY_FILE") is True

    def test_matches_filename_non_key_file(self):
        """
        GIVEN a PrivateKeyMatcher
        WHEN checking regular file
        THEN it does not match
        """
        matcher = PrivateKeyMatcher()
        assert matcher.matches_filename("readme.txt") is False
        assert matcher.matches_filename("config.json") is False

    def test_extract_secrets_id_rsa(self, tmp_path: Path):
        """
        GIVEN an id_rsa file with valid key content
        WHEN extracting secrets
        THEN yields the key content
        """
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        key_file = ssh_dir / "id_rsa"
        key_file.write_text(SAMPLE_RSA_KEY)

        matcher = PrivateKeyMatcher()
        secrets = list(matcher.extract_secrets(key_file, set()))

        assert len(secrets) == 1
        assert secrets[0].metadata.source_type == SourceType.PRIVATE_KEY
        assert "id_rsa" in secrets[0].metadata.secret_name
        assert "BEGIN RSA PRIVATE KEY" in secrets[0].value

    def test_extract_secrets_openssh_key(self, tmp_path: Path):
        """
        GIVEN an OpenSSH private key file
        WHEN extracting secrets
        THEN yields the key content
        """
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        key_file = ssh_dir / "id_ed25519"
        key_file.write_text(SAMPLE_OPENSSH_KEY)

        matcher = PrivateKeyMatcher()
        secrets = list(matcher.extract_secrets(key_file, set()))

        assert len(secrets) == 1
        assert "id_ed25519" in secrets[0].metadata.secret_name

    def test_extract_secrets_pem_file(self, tmp_path: Path):
        """
        GIVEN a .pem file with valid key content
        WHEN extracting secrets
        THEN yields the key content
        """
        key_file = tmp_path / "server.pem"
        key_file.write_text(SAMPLE_RSA_KEY)

        matcher = PrivateKeyMatcher()
        secrets = list(matcher.extract_secrets(key_file, set()))

        assert len(secrets) == 1
        assert secrets[0].metadata.secret_name == "server.pem"

    def test_extract_secrets_ignores_non_key_content(self, tmp_path: Path):
        """
        GIVEN a .pem file without key markers
        WHEN extracting secrets
        THEN ignores it
        """
        key_file = tmp_path / "not_a_key.pem"
        key_file.write_text("This is not a private key")

        matcher = PrivateKeyMatcher()
        secrets = list(matcher.extract_secrets(key_file, set()))

        assert len(secrets) == 0

    def test_extract_secrets_ignores_empty_files(self, tmp_path: Path):
        """
        GIVEN an empty key file
        WHEN extracting secrets
        THEN ignores it
        """
        key_file = tmp_path / "id_rsa"
        key_file.write_text("")

        matcher = PrivateKeyMatcher()
        secrets = list(matcher.extract_secrets(key_file, set()))

        assert len(secrets) == 0

    def test_extract_secrets_ignores_large_files(self, tmp_path: Path):
        """
        GIVEN a .pem file larger than MAX_KEY_FILE_SIZE (10KB)
        WHEN extracting secrets
        THEN ignores it
        """
        # Create a file larger than 10KB
        large_content = SAMPLE_RSA_KEY + ("x" * 15000)
        key_file = tmp_path / "large.pem"
        key_file.write_text(large_content)

        matcher = PrivateKeyMatcher()
        secrets = list(matcher.extract_secrets(key_file, set()))

        assert len(secrets) == 0

    def test_extract_secrets_skips_seen_paths(self, tmp_path: Path):
        """
        GIVEN a key file that's already in seen_paths
        WHEN extracting secrets
        THEN skips it
        """
        key_file = tmp_path / "id_rsa"
        key_file.write_text(SAMPLE_RSA_KEY)

        seen_paths: Set[Path] = {key_file}
        matcher = PrivateKeyMatcher(seen_paths=seen_paths)
        secrets = list(matcher.extract_secrets(key_file, set()))

        assert len(secrets) == 0

    def test_extract_secrets_respects_exclusion_patterns(self, tmp_path: Path):
        """
        GIVEN a key file matching exclusion pattern
        WHEN extracting secrets
        THEN skips it
        """
        tests_dir = tmp_path / "tests" / "fixtures"
        tests_dir.mkdir(parents=True)
        key_file = tests_dir / "test.pem"
        key_file.write_text(SAMPLE_RSA_KEY)

        exclusion_regexes = init_exclusion_regexes(["**/tests/**/*"])

        matcher = PrivateKeyMatcher()
        secrets = list(matcher.extract_secrets(key_file, exclusion_regexes))

        assert len(secrets) == 0

    def test_allowed_dot_directories(self):
        """
        GIVEN a PrivateKeyMatcher
        WHEN accessing allowed_dot_directories
        THEN it returns expected directories
        """
        matcher = PrivateKeyMatcher()
        allowed = matcher.allowed_dot_directories

        assert ".ssh" in allowed
        assert ".gnupg" in allowed
        assert ".ssl" in allowed
        assert ".certs" in allowed
        assert ".aws" in allowed
        assert ".config" in allowed

    def test_extract_secrets_ignores_public_certificates(self, tmp_path: Path):
        """
        GIVEN a .pem file containing only a public certificate (no private key)
        WHEN extracting secrets
        THEN ignores it (public certs are not secrets)
        """
        cert_file = tmp_path / "ca_certificate.pem"
        cert_file.write_text(SAMPLE_PUBLIC_CERTIFICATE)

        matcher = PrivateKeyMatcher()
        secrets = list(matcher.extract_secrets(cert_file, set()))

        assert len(secrets) == 0

    def test_extract_secrets_detects_combined_cert_and_key(self, tmp_path: Path):
        """
        GIVEN a .pem file containing both a certificate and a private key
        WHEN extracting secrets
        THEN detects it (private key is present)
        """
        combined_file = tmp_path / "server_bundle.pem"
        combined_file.write_text(SAMPLE_CERT_WITH_KEY)

        matcher = PrivateKeyMatcher()
        secrets = list(matcher.extract_secrets(combined_file, set()))

        assert len(secrets) == 1
        assert "BEGIN RSA PRIVATE KEY" in secrets[0].value
