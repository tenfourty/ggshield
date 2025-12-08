"""
Tests for platform-aware path resolution.

These tests verify that credential paths are resolved correctly
on different platforms (macOS, Linux, Windows).
"""

from pathlib import Path
from unittest.mock import patch

from ggshield.verticals.machine.sources.platform_paths import (
    CredentialPaths,
    get_appdata,
    get_localappdata,
    get_os_name,
    is_linux,
    is_macos,
    is_windows,
)


class TestPlatformDetection:
    """Test platform detection helpers."""

    def test_is_macos_on_darwin(self):
        """
        GIVEN get_os_name returns darwin
        WHEN checking platform helpers
        THEN is_macos returns True, others return False
        """
        with patch(
            "ggshield.verticals.machine.sources.platform_paths.get_os_name",
            return_value="darwin",
        ):
            # Clear the lru_cache to ensure our mock is used
            get_os_name.cache_clear()
            assert is_macos() is True
            assert is_windows() is False
            assert is_linux() is False

    def test_is_windows_on_windows(self):
        """
        GIVEN get_os_name returns windows
        WHEN checking platform helpers
        THEN is_windows returns True, others return False
        """
        with patch(
            "ggshield.verticals.machine.sources.platform_paths.get_os_name",
            return_value="windows",
        ):
            get_os_name.cache_clear()
            assert is_macos() is False
            assert is_windows() is True
            assert is_linux() is False

    def test_is_linux_on_ubuntu(self):
        """
        GIVEN get_os_name returns a Linux distro name
        WHEN checking platform helpers
        THEN is_linux returns True, others return False
        """
        with patch(
            "ggshield.verticals.machine.sources.platform_paths.get_os_name",
            return_value="ubuntu",
        ):
            get_os_name.cache_clear()
            assert is_macos() is False
            assert is_windows() is False
            assert is_linux() is True

    def test_is_linux_on_fedora(self):
        """
        GIVEN get_os_name returns fedora
        WHEN checking platform helpers
        THEN is_linux returns True
        """
        with patch(
            "ggshield.verticals.machine.sources.platform_paths.get_os_name",
            return_value="fedora",
        ):
            get_os_name.cache_clear()
            assert is_linux() is True


class TestGetAppdata:
    """Test Windows APPDATA helpers."""

    def test_get_appdata_with_env_set(self):
        """
        GIVEN APPDATA environment variable is set
        WHEN calling get_appdata
        THEN returns the path
        """
        with patch.dict("os.environ", {"APPDATA": "C:\\Users\\Test\\AppData\\Roaming"}):
            result = get_appdata()
            assert result == Path("C:\\Users\\Test\\AppData\\Roaming")

    def test_get_appdata_without_env_set(self):
        """
        GIVEN APPDATA environment variable is not set
        WHEN calling get_appdata
        THEN returns None
        """
        with patch.dict("os.environ", {}, clear=True):
            result = get_appdata()
            assert result is None

    def test_get_localappdata_with_env_set(self):
        """
        GIVEN LOCALAPPDATA environment variable is set
        WHEN calling get_localappdata
        THEN returns the path
        """
        with patch.dict(
            "os.environ", {"LOCALAPPDATA": "C:\\Users\\Test\\AppData\\Local"}
        ):
            result = get_localappdata()
            assert result == Path("C:\\Users\\Test\\AppData\\Local")


class TestCredentialPaths:
    """Test CredentialPaths class."""

    def test_cross_platform_paths(self, tmp_path: Path):
        """
        GIVEN a CredentialPaths instance with custom home dir
        WHEN accessing cross-platform paths
        THEN returns paths relative to home regardless of platform
        """
        paths = CredentialPaths(home_dir=tmp_path)

        # These paths are the same on all platforms
        assert paths.aws_credentials == tmp_path / ".aws" / "credentials"
        assert paths.docker_config == tmp_path / ".docker" / "config.json"
        assert paths.kube_config == tmp_path / ".kube" / "config"
        assert paths.vault_token == tmp_path / ".vault-token"
        assert paths.pypirc == tmp_path / ".pypirc"

    def test_netrc_on_unix(self, tmp_path: Path):
        """
        GIVEN running on macOS or Linux
        WHEN accessing netrc path
        THEN returns ~/.netrc
        """
        with patch(
            "ggshield.verticals.machine.sources.platform_paths.get_os_name",
            return_value="darwin",
        ):
            get_os_name.cache_clear()
            paths = CredentialPaths(home_dir=tmp_path)
            assert paths.netrc == tmp_path / ".netrc"

    def test_netrc_on_windows(self, tmp_path: Path):
        """
        GIVEN running on Windows
        WHEN accessing netrc path
        THEN returns ~/_netrc (Windows convention)
        """
        with patch(
            "ggshield.verticals.machine.sources.platform_paths.get_os_name",
            return_value="windows",
        ):
            get_os_name.cache_clear()
            paths = CredentialPaths(home_dir=tmp_path)
            assert paths.netrc == tmp_path / "_netrc"

    def test_gcp_adc_on_linux(self, tmp_path: Path):
        """
        GIVEN running on Linux
        WHEN accessing GCP ADC path
        THEN returns ~/.config/gcloud/application_default_credentials.json
        """
        with patch(
            "ggshield.verticals.machine.sources.platform_paths.get_os_name",
            return_value="ubuntu",
        ):
            get_os_name.cache_clear()
            paths = CredentialPaths(home_dir=tmp_path)
            assert paths.gcp_adc == (
                tmp_path / ".config" / "gcloud" / "application_default_credentials.json"
            )

    def test_gcp_adc_on_windows(self, tmp_path: Path):
        """
        GIVEN running on Windows with APPDATA set
        WHEN accessing GCP ADC path
        THEN returns %APPDATA%/gcloud/application_default_credentials.json
        """
        appdata = tmp_path / "AppData" / "Roaming"
        with (
            patch(
                "ggshield.verticals.machine.sources.platform_paths.get_os_name",
                return_value="windows",
            ),
            patch(
                "ggshield.verticals.machine.sources.platform_paths.get_appdata",
                return_value=appdata,
            ),
        ):
            get_os_name.cache_clear()
            paths = CredentialPaths(home_dir=tmp_path)
            assert paths.gcp_adc == (
                appdata / "gcloud" / "application_default_credentials.json"
            )

    def test_github_cli_on_unix(self, tmp_path: Path):
        """
        GIVEN running on macOS or Linux
        WHEN accessing GitHub CLI hosts path
        THEN returns ~/.config/gh/hosts.yml
        """
        with patch(
            "ggshield.verticals.machine.sources.platform_paths.get_os_name",
            return_value="darwin",
        ):
            get_os_name.cache_clear()
            paths = CredentialPaths(home_dir=tmp_path)
            assert paths.github_cli == tmp_path / ".config" / "gh" / "hosts.yml"

    def test_github_cli_on_windows(self, tmp_path: Path):
        """
        GIVEN running on Windows with APPDATA set
        WHEN accessing GitHub CLI hosts path
        THEN returns %APPDATA%/GitHub CLI/hosts.yml
        """
        appdata = tmp_path / "AppData" / "Roaming"
        with (
            patch(
                "ggshield.verticals.machine.sources.platform_paths.get_os_name",
                return_value="windows",
            ),
            patch(
                "ggshield.verticals.machine.sources.platform_paths.get_appdata",
                return_value=appdata,
            ),
        ):
            get_os_name.cache_clear()
            paths = CredentialPaths(home_dir=tmp_path)
            assert paths.github_cli == appdata / "GitHub CLI" / "hosts.yml"

    def test_app_support_on_macos(self, tmp_path: Path):
        """
        GIVEN running on macOS
        WHEN accessing cursor_state_db path
        THEN returns ~/Library/Application Support/Cursor/...
        """
        with patch(
            "ggshield.verticals.machine.sources.platform_paths.get_os_name",
            return_value="darwin",
        ):
            get_os_name.cache_clear()
            paths = CredentialPaths(home_dir=tmp_path)
            assert paths.cursor_state_db == (
                tmp_path
                / "Library"
                / "Application Support"
                / "Cursor"
                / "User"
                / "globalStorage"
                / "state.vscdb"
            )

    def test_app_support_on_linux(self, tmp_path: Path):
        """
        GIVEN running on Linux
        WHEN accessing cursor_state_db path
        THEN returns ~/.config/Cursor/...
        """
        with patch(
            "ggshield.verticals.machine.sources.platform_paths.get_os_name",
            return_value="ubuntu",
        ):
            get_os_name.cache_clear()
            paths = CredentialPaths(home_dir=tmp_path)
            assert paths.cursor_state_db == (
                tmp_path
                / ".config"
                / "Cursor"
                / "User"
                / "globalStorage"
                / "state.vscdb"
            )

    def test_app_support_on_windows(self, tmp_path: Path):
        """
        GIVEN running on Windows with APPDATA set
        WHEN accessing cursor_state_db path
        THEN returns %APPDATA%/Cursor/...
        """
        appdata = tmp_path / "AppData" / "Roaming"
        with (
            patch(
                "ggshield.verticals.machine.sources.platform_paths.get_os_name",
                return_value="windows",
            ),
            patch(
                "ggshield.verticals.machine.sources.platform_paths.get_appdata",
                return_value=appdata,
            ),
        ):
            get_os_name.cache_clear()
            paths = CredentialPaths(home_dir=tmp_path)
            assert paths.cursor_state_db == (
                appdata / "Cursor" / "User" / "globalStorage" / "state.vscdb"
            )
