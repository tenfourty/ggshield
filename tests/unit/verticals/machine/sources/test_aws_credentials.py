"""
Tests for AWS credentials secret source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.aws_credentials import AwsCredentialsSource


class TestAwsCredentialsSource:
    """Tests for AwsCredentialsSource."""

    def test_source_type(self):
        """
        GIVEN an AwsCredentialsSource
        WHEN accessing source_type
        THEN it returns AWS_CREDENTIALS
        """
        source = AwsCredentialsSource()
        assert source.source_type == SourceType.AWS_CREDENTIALS

    def test_gather_with_secret_access_key(self, tmp_path: Path):
        """
        GIVEN an AWS credentials file with secret access key
        WHEN gathering secrets
        THEN yields the secret access key
        """
        aws_dir = tmp_path / ".aws"
        aws_dir.mkdir()
        credentials_content = """
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""
        (aws_dir / "credentials").write_text(credentials_content)

        source = AwsCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert secrets[0].metadata.source_type == SourceType.AWS_CREDENTIALS
        assert "aws_secret_access_key" in secrets[0].metadata.secret_name

    def test_gather_with_session_token(self, tmp_path: Path):
        """
        GIVEN an AWS credentials file with session token
        WHEN gathering secrets
        THEN yields the session token
        """
        aws_dir = tmp_path / ".aws"
        aws_dir.mkdir()
        credentials_content = """
[default]
aws_access_key_id = ASIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws_session_token = FwoGZXIvYXdzEBYaDKb...truncated...
"""
        (aws_dir / "credentials").write_text(credentials_content)

        source = AwsCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 2
        values = {s.value for s in secrets}
        assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in values
        assert "FwoGZXIvYXdzEBYaDKb...truncated..." in values

    def test_gather_with_multiple_profiles(self, tmp_path: Path):
        """
        GIVEN an AWS credentials file with multiple profiles
        WHEN gathering secrets
        THEN yields secrets from all profiles
        """
        aws_dir = tmp_path / ".aws"
        aws_dir.mkdir()
        credentials_content = """
[default]
aws_access_key_id = AKIADEFAULT
aws_secret_access_key = secretkey1

[production]
aws_access_key_id = AKIAPRODUCTION
aws_secret_access_key = secretkey2
"""
        (aws_dir / "credentials").write_text(credentials_content)

        source = AwsCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 2
        # Check profile names are in secret names
        secret_names = [s.metadata.secret_name for s in secrets]
        assert any("default" in name for name in secret_names)
        assert any("production" in name for name in secret_names)

    def test_gather_ignores_access_key_id(self, tmp_path: Path):
        """
        GIVEN an AWS credentials file with only access key ID
        WHEN gathering secrets
        THEN ignores it (not a secret)
        """
        aws_dir = tmp_path / ".aws"
        aws_dir.mkdir()
        credentials_content = """
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
"""
        (aws_dir / "credentials").write_text(credentials_content)

        source = AwsCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_no_credentials_file(self, tmp_path: Path):
        """
        GIVEN no AWS credentials file exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = AwsCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_credentials(self, tmp_path: Path):
        """
        GIVEN an empty AWS credentials file
        WHEN gathering secrets
        THEN yields nothing
        """
        aws_dir = tmp_path / ".aws"
        aws_dir.mkdir()
        (aws_dir / "credentials").write_text("")

        source = AwsCredentialsSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0
