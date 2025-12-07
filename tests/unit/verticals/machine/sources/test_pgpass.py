"""
Tests for PostgreSQL pgpass secret source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.pgpass import PgpassSource


class TestPgpassSource:
    """Tests for PgpassSource."""

    def test_source_type(self):
        """
        GIVEN a PgpassSource
        WHEN accessing source_type
        THEN it returns PGPASS
        """
        source = PgpassSource()
        assert source.source_type == SourceType.PGPASS

    def test_gather_with_password(self, tmp_path: Path):
        """
        GIVEN a .pgpass file with credentials
        WHEN gathering secrets
        THEN yields the password
        """
        pgpass_content = "localhost:5432:mydb:myuser:secretpassword"
        (tmp_path / ".pgpass").write_text(pgpass_content)

        source = PgpassSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "secretpassword"
        assert secrets[0].metadata.source_type == SourceType.PGPASS
        assert "localhost" in secrets[0].metadata.secret_name

    def test_gather_multiple_entries(self, tmp_path: Path):
        """
        GIVEN a .pgpass file with multiple entries
        WHEN gathering secrets
        THEN yields all passwords
        """
        pgpass_content = """localhost:5432:db1:user1:pass1
192.168.1.1:5432:db2:user2:pass2
*:*:*:admin:adminpass"""
        (tmp_path / ".pgpass").write_text(pgpass_content)

        source = PgpassSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 3
        values = {s.value for s in secrets}
        assert "pass1" in values
        assert "pass2" in values
        assert "adminpass" in values

    def test_gather_wildcard_entries(self, tmp_path: Path):
        """
        GIVEN a .pgpass file with wildcard entries
        WHEN gathering secrets
        THEN yields the password with wildcard info
        """
        pgpass_content = "*:*:*:postgres:superpass"
        (tmp_path / ".pgpass").write_text(pgpass_content)

        source = PgpassSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "superpass"

    def test_gather_skips_comments(self, tmp_path: Path):
        """
        GIVEN a .pgpass file with comments
        WHEN gathering secrets
        THEN skips comment lines
        """
        pgpass_content = """# This is a comment
localhost:5432:mydb:user:pass123
# Another comment"""
        (tmp_path / ".pgpass").write_text(pgpass_content)

        source = PgpassSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "pass123"

    def test_gather_no_pgpass_file(self, tmp_path: Path):
        """
        GIVEN no .pgpass file exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = PgpassSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_pgpass(self, tmp_path: Path):
        """
        GIVEN an empty .pgpass file
        WHEN gathering secrets
        THEN yields nothing
        """
        (tmp_path / ".pgpass").write_text("")

        source = PgpassSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_malformed_line(self, tmp_path: Path):
        """
        GIVEN a .pgpass file with malformed lines (fewer than 5 fields)
        WHEN gathering secrets
        THEN skips malformed lines but accepts passwords with colons
        """
        pgpass_content = """localhost:5432:mydb:user
too:few:fields
valid:5432:db:user:validpass"""
        (tmp_path / ".pgpass").write_text(pgpass_content)

        source = PgpassSource(home_dir=tmp_path)
        secrets = list(source.gather())

        # Only the valid line should produce a secret
        assert len(secrets) == 1
        assert secrets[0].value == "validpass"

    def test_gather_password_with_colons(self, tmp_path: Path):
        """
        GIVEN a .pgpass file with a password containing colons
        WHEN gathering secrets
        THEN yields the full password including colons
        """
        pgpass_content = "localhost:5432:db:user:pass:with:colons"
        (tmp_path / ".pgpass").write_text(pgpass_content)

        source = PgpassSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "pass:with:colons"
