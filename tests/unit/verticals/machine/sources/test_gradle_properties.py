"""
Tests for Gradle properties credentials source.
"""

from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.gradle_properties import GradlePropertiesSource


class TestGradlePropertiesSource:
    """Tests for GradlePropertiesSource."""

    def test_source_type(self):
        """
        GIVEN a GradlePropertiesSource
        WHEN accessing source_type
        THEN it returns GRADLE_PROPERTIES
        """
        source = GradlePropertiesSource()
        assert source.source_type == SourceType.GRADLE_PROPERTIES

    def test_gather_with_password(self, tmp_path: Path):
        """
        GIVEN a gradle.properties with password
        WHEN gathering secrets
        THEN yields the password
        """
        gradle_dir = tmp_path / ".gradle"
        gradle_dir.mkdir()
        props_content = """
# Gradle user properties
mavenPassword=secret123
"""
        (gradle_dir / "gradle.properties").write_text(props_content)

        source = GradlePropertiesSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "secret123"
        assert secrets[0].metadata.source_type == SourceType.GRADLE_PROPERTIES

    def test_gather_with_multiple_secrets(self, tmp_path: Path):
        """
        GIVEN a gradle.properties with multiple secret properties
        WHEN gathering secrets
        THEN yields all secrets
        """
        gradle_dir = tmp_path / ".gradle"
        gradle_dir.mkdir()
        props_content = """
mavenPassword=pass1
ossrhPassword=pass2
signingKey=key123
apiToken=token456
"""
        (gradle_dir / "gradle.properties").write_text(props_content)

        source = GradlePropertiesSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 4
        values = {s.value for s in secrets}
        assert "pass1" in values
        assert "pass2" in values
        assert "key123" in values
        assert "token456" in values

    def test_gather_ignores_non_secrets(self, tmp_path: Path):
        """
        GIVEN a gradle.properties with non-secret properties
        WHEN gathering secrets
        THEN ignores them
        """
        gradle_dir = tmp_path / ".gradle"
        gradle_dir.mkdir()
        props_content = """
org.gradle.daemon=true
org.gradle.parallel=true
mavenUrl=https://repo.example.com
mavenPassword=secretvalue
"""
        (gradle_dir / "gradle.properties").write_text(props_content)

        source = GradlePropertiesSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "secretvalue"

    def test_gather_handles_equals_in_value(self, tmp_path: Path):
        """
        GIVEN a gradle.properties with = in the value
        WHEN gathering secrets
        THEN extracts the full value
        """
        gradle_dir = tmp_path / ".gradle"
        gradle_dir.mkdir()
        props_content = "apiToken=abc=def=ghi"
        (gradle_dir / "gradle.properties").write_text(props_content)

        source = GradlePropertiesSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "abc=def=ghi"

    def test_gather_ignores_comments(self, tmp_path: Path):
        """
        GIVEN a gradle.properties with commented secrets
        WHEN gathering secrets
        THEN ignores comments
        """
        gradle_dir = tmp_path / ".gradle"
        gradle_dir.mkdir()
        props_content = """
# mavenPassword=oldpassword
mavenPassword=newpassword
"""
        (gradle_dir / "gradle.properties").write_text(props_content)

        source = GradlePropertiesSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "newpassword"

    def test_gather_no_properties_file(self, tmp_path: Path):
        """
        GIVEN no gradle.properties exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = GradlePropertiesSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_properties(self, tmp_path: Path):
        """
        GIVEN an empty gradle.properties
        WHEN gathering secrets
        THEN yields nothing
        """
        gradle_dir = tmp_path / ".gradle"
        gradle_dir.mkdir()
        (gradle_dir / "gradle.properties").write_text("")

        source = GradlePropertiesSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_with_colon_separator(self, tmp_path: Path):
        """
        GIVEN a gradle.properties with colon separator
        WHEN gathering secrets
        THEN extracts the value
        """
        gradle_dir = tmp_path / ".gradle"
        gradle_dir.mkdir()
        props_content = "mavenPassword:colonseparated"
        (gradle_dir / "gradle.properties").write_text(props_content)

        source = GradlePropertiesSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "colonseparated"
