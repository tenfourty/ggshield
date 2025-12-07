"""
Tests for netrc secret source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.netrc import NetrcSource


class TestNetrcSource:
    """Tests for NetrcSource."""

    def test_source_type(self):
        """
        GIVEN a NetrcSource
        WHEN accessing source_type
        THEN it returns NETRC
        """
        source = NetrcSource()
        assert source.source_type == SourceType.NETRC

    def test_gather_with_password(self, tmp_path: Path):
        """
        GIVEN a .netrc file with machine credentials
        WHEN gathering secrets
        THEN yields the password
        """
        netrc_content = """
machine github.com
login myuser
password ghp_xxxxxxxxxxxxxxxxxxxx
"""
        (tmp_path / ".netrc").write_text(netrc_content)

        source = NetrcSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "ghp_xxxxxxxxxxxxxxxxxxxx"
        assert secrets[0].metadata.source_type == SourceType.NETRC
        assert "github.com" in secrets[0].metadata.secret_name

    def test_gather_single_line_format(self, tmp_path: Path):
        """
        GIVEN a .netrc file with single-line format
        WHEN gathering secrets
        THEN yields the password
        """
        netrc_content = (
            "machine api.heroku.com login user@example.com password abcd1234"
        )
        (tmp_path / ".netrc").write_text(netrc_content)

        source = NetrcSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "abcd1234"

    def test_gather_multiple_machines(self, tmp_path: Path):
        """
        GIVEN a .netrc file with multiple machines
        WHEN gathering secrets
        THEN yields all passwords
        """
        netrc_content = """
machine github.com login user1 password pass1
machine gitlab.com login user2 password pass2
machine bitbucket.org login user3 password pass3
"""
        (tmp_path / ".netrc").write_text(netrc_content)

        source = NetrcSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 3
        values = {s.value for s in secrets}
        assert "pass1" in values
        assert "pass2" in values
        assert "pass3" in values

    def test_gather_default_machine(self, tmp_path: Path):
        """
        GIVEN a .netrc file with default entry
        WHEN gathering secrets
        THEN yields the default password
        """
        netrc_content = """
default login anonymous password guest@example.com
"""
        (tmp_path / ".netrc").write_text(netrc_content)

        source = NetrcSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "guest@example.com"
        assert "default" in secrets[0].metadata.secret_name

    def test_gather_windows_netrc(self, tmp_path: Path):
        """
        GIVEN a _netrc file (Windows format)
        WHEN gathering secrets
        THEN yields the password
        """
        netrc_content = "machine example.com login user password secret123"
        (tmp_path / "_netrc").write_text(netrc_content)

        source = NetrcSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "secret123"

    def test_gather_no_netrc_file(self, tmp_path: Path):
        """
        GIVEN no .netrc file exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = NetrcSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_netrc(self, tmp_path: Path):
        """
        GIVEN an empty .netrc file
        WHEN gathering secrets
        THEN yields nothing
        """
        (tmp_path / ".netrc").write_text("")

        source = NetrcSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_no_password(self, tmp_path: Path):
        """
        GIVEN a .netrc file with only machine and login
        WHEN gathering secrets
        THEN yields nothing
        """
        netrc_content = "machine example.com login user"
        (tmp_path / ".netrc").write_text(netrc_content)

        source = NetrcSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0
