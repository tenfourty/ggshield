"""
Tests for PyPI (.pypirc) secret source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.pypirc import PypircSource


class TestPypircSource:
    """Tests for PypircSource."""

    def test_source_type(self):
        """
        GIVEN a PypircSource
        WHEN accessing source_type
        THEN it returns PYPIRC
        """
        source = PypircSource()
        assert source.source_type == SourceType.PYPIRC

    def test_gather_with_password(self, tmp_path: Path):
        """
        GIVEN a .pypirc file with password
        WHEN gathering secrets
        THEN yields the password
        """
        pypirc_content = """
[distutils]
index-servers = pypi

[pypi]
username = myuser
password = supersecretpassword
"""
        (tmp_path / ".pypirc").write_text(pypirc_content)

        source = PypircSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "supersecretpassword"
        assert secrets[0].metadata.source_type == SourceType.PYPIRC
        assert "pypi" in secrets[0].metadata.secret_name

    def test_gather_with_token(self, tmp_path: Path):
        """
        GIVEN a .pypirc file with API token
        WHEN gathering secrets
        THEN yields the token
        """
        pypirc_content = """
[pypi]
username = __token__
token = pypi-AgEIcHlwaS5vcmcCJGNl...truncated...
"""
        (tmp_path / ".pypirc").write_text(pypirc_content)

        source = PypircSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "pypi-AgEIcHlwaS5vcmcCJGNl...truncated..."

    def test_gather_with_multiple_servers(self, tmp_path: Path):
        """
        GIVEN a .pypirc file with multiple servers
        WHEN gathering secrets
        THEN yields all passwords/tokens
        """
        pypirc_content = """
[distutils]
index-servers = pypi testpypi

[pypi]
username = user1
password = password1

[testpypi]
username = user2
password = password2
"""
        (tmp_path / ".pypirc").write_text(pypirc_content)

        source = PypircSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 2
        values = {s.value for s in secrets}
        assert "password1" in values
        assert "password2" in values

    def test_gather_ignores_non_secret_keys(self, tmp_path: Path):
        """
        GIVEN a .pypirc file with non-secret configuration
        WHEN gathering secrets
        THEN ignores those values
        """
        pypirc_content = """
[pypi]
username = myuser
repository = https://upload.pypi.org/legacy/
"""
        (tmp_path / ".pypirc").write_text(pypirc_content)

        source = PypircSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_no_pypirc_file(self, tmp_path: Path):
        """
        GIVEN no .pypirc file exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = PypircSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_pypirc(self, tmp_path: Path):
        """
        GIVEN an empty .pypirc file
        WHEN gathering secrets
        THEN yields nothing
        """
        (tmp_path / ".pypirc").write_text("")

        source = PypircSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0
