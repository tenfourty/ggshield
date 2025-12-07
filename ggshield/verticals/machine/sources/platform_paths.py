"""Platform-aware credential path helpers for machine scan.

This module provides cross-platform path resolution for credential files,
using the existing OS detection from ggshield.utils.os.
"""

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from ggshield.utils.os import get_os_info


@lru_cache(maxsize=1)
def get_os_name() -> str:
    """Get OS name (cached).

    Returns:
        'darwin' for macOS, 'windows' for Windows, or Linux distro name (e.g. 'ubuntu')
    """
    os_name, _ = get_os_info()
    return os_name


def is_macos() -> bool:
    """Check if running on macOS."""
    return get_os_name() == "darwin"


def is_windows() -> bool:
    """Check if running on Windows."""
    return get_os_name() == "windows"


def is_linux() -> bool:
    """Check if running on Linux (any distro)."""
    return get_os_name() not in ("darwin", "windows")


def get_appdata() -> Optional[Path]:
    """Get Windows %APPDATA% directory.

    Returns:
        Path to APPDATA on Windows, None on other platforms or if not set.
    """
    appdata = os.environ.get("APPDATA")
    return Path(appdata) if appdata else None


def get_localappdata() -> Optional[Path]:
    """Get Windows %LOCALAPPDATA% directory.

    Returns:
        Path to LOCALAPPDATA on Windows, None on other platforms or if not set.
    """
    local = os.environ.get("LOCALAPPDATA")
    return Path(local) if local else None


def get_programdata() -> Optional[Path]:
    """Get Windows %PROGRAMDATA% directory.

    Returns:
        Path to PROGRAMDATA on Windows, None on other platforms or if not set.
    """
    programdata = os.environ.get("PROGRAMDATA")
    return Path(programdata) if programdata else None


class CredentialPaths:
    """Platform-aware credential file paths.

    This class provides properties that return the correct path for various
    credential files based on the current operating system.

    Example:
        paths = CredentialPaths()
        if paths.aws_credentials.exists():
            # scan AWS credentials
            pass
    """

    def __init__(self, home_dir: Optional[Path] = None):
        """Initialise with optional custom home directory.

        Args:
            home_dir: Override home directory (useful for testing)
        """
        self.home = home_dir or Path.home()
        self._os_name = get_os_name()

    def _app_support(self, app_name: str) -> Optional[Path]:
        """Get app data directory for the current platform.

        Args:
            app_name: Application name

        Returns:
            Platform-specific application data directory, or None if unavailable.
        """
        if self._os_name == "windows":
            appdata = get_appdata()
            return appdata / app_name if appdata else None
        elif self._os_name == "darwin":
            return self.home / "Library" / "Application Support" / app_name
        else:
            # Linux and other Unix-like systems
            return self.home / ".config" / app_name

    def _local_app_data(self, app_name: str) -> Optional[Path]:
        """Get local app data directory (Windows LOCALAPPDATA equivalent).

        Args:
            app_name: Application name

        Returns:
            Platform-specific local application data directory.
        """
        if self._os_name == "windows":
            local = get_localappdata()
            return local / app_name if local else None
        elif self._os_name == "darwin":
            # macOS uses same location for both
            return self.home / "Library" / "Application Support" / app_name
        else:
            # Linux: use .local/share or .config
            return self.home / ".local" / "share" / app_name

    # =========================================================================
    # Cross-platform paths (same structure on all OSes)
    # =========================================================================

    @property
    def aws_credentials(self) -> Path:
        """AWS credentials file (~/.aws/credentials)."""
        return self.home / ".aws" / "credentials"

    @property
    def aws_config(self) -> Path:
        """AWS config file (~/.aws/config)."""
        return self.home / ".aws" / "config"

    @property
    def docker_config(self) -> Path:
        """Docker config file (~/.docker/config.json)."""
        return self.home / ".docker" / "config.json"

    @property
    def kube_config(self) -> Path:
        """Kubernetes config file (~/.kube/config)."""
        return self.home / ".kube" / "config"

    @property
    def vault_token(self) -> Path:
        """HashiCorp Vault token file (~/.vault-token)."""
        return self.home / ".vault-token"

    @property
    def ssh_dir(self) -> Path:
        """SSH directory (~/.ssh/)."""
        return self.home / ".ssh"

    @property
    def gnupg_dir(self) -> Path:
        """GnuPG directory (~/.gnupg/)."""
        return self.home / ".gnupg"

    @property
    def pgpass(self) -> Path:
        """PostgreSQL password file (~/.pgpass)."""
        return self.home / ".pgpass"

    @property
    def mycnf(self) -> Path:
        """MySQL config file (~/.my.cnf)."""
        return self.home / ".my.cnf"

    @property
    def pypirc(self) -> Path:
        """PyPI config file (~/.pypirc)."""
        return self.home / ".pypirc"

    @property
    def git_credentials(self) -> Path:
        """Git credentials file (~/.git-credentials)."""
        return self.home / ".git-credentials"

    @property
    def dbt_profiles(self) -> Path:
        """dbt profiles file (~/.dbt/profiles.yml)."""
        return self.home / ".dbt" / "profiles.yml"

    @property
    def oci_config(self) -> Path:
        """Oracle Cloud Infrastructure config (~/.oci/config)."""
        return self.home / ".oci" / "config"

    @property
    def aider_config(self) -> Path:
        """Aider config file (~/.aider.conf.yml)."""
        return self.home / ".aider.conf.yml"

    # =========================================================================
    # Platform-specific paths
    # =========================================================================

    @property
    def netrc(self) -> Path:
        """Netrc file (~/.netrc on Unix, ~/_netrc on Windows)."""
        if self._os_name == "windows":
            return self.home / "_netrc"
        return self.home / ".netrc"

    @property
    def github_cli(self) -> Path:
        """GitHub CLI hosts file."""
        if self._os_name == "windows":
            appdata = get_appdata()
            if appdata:
                return appdata / "GitHub CLI" / "hosts.yml"
        return self.home / ".config" / "gh" / "hosts.yml"

    @property
    def gitlab_cli(self) -> Path:
        """GitLab CLI (glab) config file."""
        if self._os_name == "windows":
            appdata = get_appdata()
            if appdata:
                return appdata / "glab-cli" / "config.yml"
        return self.home / ".config" / "glab-cli" / "config.yml"

    @property
    def circleci_cli(self) -> Path:
        """CircleCI CLI config file."""
        return self.home / ".circleci" / "cli.yml"

    @property
    def travis_cli(self) -> Path:
        """Travis CI CLI config file."""
        return self.home / ".travis" / "config.yml"

    @property
    def slack_credentials(self) -> Path:
        """Slack CLI credentials file."""
        return self.home / ".slack" / "credentials.json"

    # =========================================================================
    # Cloud provider credentials
    # =========================================================================

    @property
    def gcp_adc(self) -> Path:
        """GCP Application Default Credentials."""
        if self._os_name == "windows":
            appdata = get_appdata()
            if appdata:
                return appdata / "gcloud" / "application_default_credentials.json"
        return self.home / ".config" / "gcloud" / "application_default_credentials.json"

    @property
    def gcp_credentials_db(self) -> Path:
        """GCP credentials database (SQLite)."""
        if self._os_name == "windows":
            appdata = get_appdata()
            if appdata:
                return appdata / "gcloud" / "credentials.db"
        return self.home / ".config" / "gcloud" / "credentials.db"

    @property
    def azure_access_tokens(self) -> Path:
        """Azure CLI access tokens (legacy)."""
        return self.home / ".azure" / "accessTokens.json"

    @property
    def azure_msal_cache(self) -> Path:
        """Azure CLI MSAL token cache."""
        return self.home / ".azure" / "msal_token_cache.json"

    @property
    def ibm_cloud_config(self) -> Path:
        """IBM Cloud CLI config."""
        return self.home / ".bluemix" / "config.json"

    @property
    def digitalocean_config(self) -> Path:
        """DigitalOcean CLI (doctl) config."""
        if self._os_name == "windows":
            appdata = get_appdata()
            if appdata:
                return appdata / "doctl" / "config.yaml"
        return self.home / ".config" / "doctl" / "config.yaml"

    # =========================================================================
    # Package manager credentials
    # =========================================================================

    @property
    def cargo_credentials(self) -> Path:
        """Cargo/crates.io credentials."""
        return self.home / ".cargo" / "credentials.toml"

    @property
    def gem_credentials(self) -> Path:
        """RubyGems credentials."""
        return self.home / ".gem" / "credentials"

    @property
    def composer_auth(self) -> Path:
        """Composer/Packagist auth."""
        return self.home / ".composer" / "auth.json"

    @property
    def maven_settings(self) -> Path:
        """Maven settings with server credentials."""
        return self.home / ".m2" / "settings.xml"

    @property
    def gradle_properties(self) -> Path:
        """Gradle properties with credentials."""
        return self.home / ".gradle" / "gradle.properties"

    @property
    def nuget_config(self) -> Path:
        """NuGet config file."""
        if self._os_name == "windows":
            appdata = get_appdata()
            if appdata:
                return appdata / "NuGet" / "NuGet.Config"
        return self.home / ".nuget" / "NuGet" / "NuGet.Config"

    @property
    def helm_registry_config(self) -> Path:
        """Helm OCI registry config."""
        if self._os_name == "windows":
            appdata = get_appdata()
            if appdata:
                return appdata / "helm" / "registry" / "config.json"
        return self.home / ".config" / "helm" / "registry" / "config.json"

    # =========================================================================
    # AI coding tool credentials
    # =========================================================================

    @property
    def claude_credentials(self) -> Path:
        """Claude Code credentials."""
        return self.home / ".claude" / "credentials.json"

    @property
    def claude_config(self) -> Path:
        """Claude Code config."""
        return self.home / ".claude" / "claude.json"

    @property
    def gemini_env(self) -> Path:
        """Gemini CLI .env file."""
        return self.home / ".gemini" / ".env"

    @property
    def continue_config(self) -> Path:
        """Continue.dev config."""
        return self.home / ".continue" / "config.yaml"

    @property
    def cursor_state_db(self) -> Optional[Path]:
        """Cursor IDE state database."""
        app_support = self._app_support("Cursor")
        if app_support:
            return app_support / "User" / "globalStorage" / "state.vscdb"
        return None

    @property
    def windsurf_mcp_config(self) -> Path:
        """Windsurf (Codeium) MCP config."""
        return self.home / ".codeium" / "windsurf" / "mcp_config.json"

    # =========================================================================
    # Messaging app directories (for token detection)
    # =========================================================================

    @property
    def discord_storage(self) -> Optional[Path]:
        """Discord Local Storage directory (contains tokens in LevelDB)."""
        app_dir = self._app_support("discord")
        if app_dir:
            return app_dir / "Local Storage" / "leveldb"
        return None

    @property
    def teams_storage(self) -> Optional[Path]:
        """Microsoft Teams Local Storage directory."""
        if self._os_name == "windows":
            appdata = get_appdata()
            if appdata:
                return appdata / "Microsoft" / "Teams" / "Local Storage" / "leveldb"
        elif self._os_name == "darwin":
            return (
                self.home
                / "Library"
                / "Application Support"
                / "Microsoft"
                / "Teams"
                / "Local Storage"
                / "leveldb"
            )
        else:
            return (
                self.home
                / ".config"
                / "Microsoft"
                / "Microsoft Teams"
                / "Local Storage"
                / "leveldb"
            )

    # =========================================================================
    # Browser user data directories
    # =========================================================================

    @property
    def chrome_user_data(self) -> Optional[Path]:
        """Chrome user data directory."""
        if self._os_name == "windows":
            local = get_localappdata()
            if local:
                return local / "Google" / "Chrome" / "User Data"
        elif self._os_name == "darwin":
            return self.home / "Library" / "Application Support" / "Google" / "Chrome"
        else:
            return self.home / ".config" / "google-chrome"

    @property
    def firefox_profiles(self) -> Optional[Path]:
        """Firefox profiles directory."""
        if self._os_name == "windows":
            appdata = get_appdata()
            if appdata:
                return appdata / "Mozilla" / "Firefox" / "Profiles"
        elif self._os_name == "darwin":
            return (
                self.home / "Library" / "Application Support" / "Firefox" / "Profiles"
            )
        else:
            return self.home / ".mozilla" / "firefox"

    # =========================================================================
    # Crypto wallet directories (detection only - contents are encrypted)
    # =========================================================================

    @property
    def electrum_wallets(self) -> Optional[Path]:
        """Electrum wallet directory."""
        if self._os_name == "windows":
            appdata = get_appdata()
            if appdata:
                return appdata / "Electrum" / "wallets"
        elif self._os_name == "darwin":
            return self.home / ".electrum" / "wallets"
        else:
            return self.home / ".electrum" / "wallets"
