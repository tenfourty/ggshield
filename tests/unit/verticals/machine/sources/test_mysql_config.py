"""
Tests for MySQL config secret source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.mysql_config import MysqlConfigSource


class TestMysqlConfigSource:
    """Tests for MysqlConfigSource."""

    def test_source_type(self):
        """
        GIVEN a MysqlConfigSource
        WHEN accessing source_type
        THEN it returns MYSQL_CONFIG
        """
        source = MysqlConfigSource()
        assert source.source_type == SourceType.MYSQL_CONFIG

    def test_gather_with_password(self, tmp_path: Path):
        """
        GIVEN a .my.cnf file with password in [client] section
        WHEN gathering secrets
        THEN yields the password
        """
        config_content = """[client]
user = myuser
password = secretpassword
host = localhost
"""
        (tmp_path / ".my.cnf").write_text(config_content)

        source = MysqlConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "secretpassword"
        assert secrets[0].metadata.source_type == SourceType.MYSQL_CONFIG
        assert "client" in secrets[0].metadata.secret_name

    def test_gather_quoted_password(self, tmp_path: Path):
        """
        GIVEN a .my.cnf file with quoted password
        WHEN gathering secrets
        THEN yields the unquoted password
        """
        config_content = """[client]
password = "my quoted password"
"""
        (tmp_path / ".my.cnf").write_text(config_content)

        source = MysqlConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "my quoted password"

    def test_gather_multiple_sections(self, tmp_path: Path):
        """
        GIVEN a .my.cnf file with passwords in multiple sections
        WHEN gathering secrets
        THEN yields all passwords
        """
        config_content = """[client]
password = clientpass

[mysql]
password = mysqlpass

[mysqldump]
password = dumppass
"""
        (tmp_path / ".my.cnf").write_text(config_content)

        source = MysqlConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 3
        values = {s.value for s in secrets}
        assert "clientpass" in values
        assert "mysqlpass" in values
        assert "dumppass" in values

    def test_gather_no_my_cnf_file(self, tmp_path: Path):
        """
        GIVEN no .my.cnf file exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = MysqlConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_my_cnf(self, tmp_path: Path):
        """
        GIVEN an empty .my.cnf file
        WHEN gathering secrets
        THEN yields nothing
        """
        (tmp_path / ".my.cnf").write_text("")

        source = MysqlConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_no_password(self, tmp_path: Path):
        """
        GIVEN a .my.cnf file without password entries
        WHEN gathering secrets
        THEN yields nothing
        """
        config_content = """[client]
user = myuser
host = localhost
"""
        (tmp_path / ".my.cnf").write_text(config_content)

        source = MysqlConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_skips_comments(self, tmp_path: Path):
        """
        GIVEN a .my.cnf file with comments
        WHEN gathering secrets
        THEN skips comment lines
        """
        config_content = """[client]
# password = notasecret
; another comment
password = realpassword
"""
        (tmp_path / ".my.cnf").write_text(config_content)

        source = MysqlConfigSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "realpassword"
