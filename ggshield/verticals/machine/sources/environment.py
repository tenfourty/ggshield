"""
Environment variable secret source.
"""

import os
from typing import Iterator

from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)
from ggshield.verticals.machine.sources.base import SecretSource


# Keys that are typically not secrets and should be excluded
EXCLUDED_ENV_KEYS = {
    # Standard shell/system
    "HOME",
    "HOSTNAME",
    "HOST",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "LOGNAME",
    "MAIL",
    "OLDPWD",
    "PATH",
    "PORT",
    "PS1",
    "PS2",
    "PWD",
    "SHELL",
    "SHLVL",
    "TERM",
    "TERM_PROGRAM",
    "TERM_PROGRAM_VERSION",
    "TMPDIR",
    "USER",
    "USERNAME",
    "_",
    # XDG directories
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_DATA_DIRS",
    "XDG_RUNTIME_DIR",
    # macOS specific
    "MANPATH",
    "INFOPATH",
    "COLORTERM",
    "COMMAND_MODE",
    "SECURITYSESSIONID",
    "LAUNCHINSTANCEID",
    "__CF_USER_TEXT_ENCODING",
    "__CFBUNDLEIDENTIFIER",
    "TERMINFO",
    "GPG_TTY",
    # Homebrew (paths, not secrets)
    "HOMEBREW_PREFIX",
    "HOMEBREW_CELLAR",
    "HOMEBREW_REPOSITORY",
    # Terminal emulators
    "GHOSTTY_RESOURCES_DIR",
    "GHOSTTY_SHELL_FEATURES",
    "GHOSTTY_BIN_DIR",
    "ITERM_SESSION_ID",
    "ITERM_PROFILE",
    "TERMINAL_EMULATOR",
    "KONSOLE_VERSION",
    "KONSOLE_DBUS_SESSION",
    # Development tools (paths/config, not secrets)
    "BUN_INSTALL",
    "PNPM_HOME",
    "VIRTUAL_ENV",
    "PDM_PROJECT_ROOT",
    "PDM_RUN_CWD",
    "CONDA_PREFIX",
    "CONDA_DEFAULT_ENV",
    "PYENV_ROOT",
    "PYENV_SHELL",
    "NVM_DIR",
    "NVM_BIN",
    "GOPATH",
    "GOROOT",
    "CARGO_HOME",
    "RUSTUP_HOME",
    # Session IDs (random but not secrets)
    "ATUIN_SESSION",
    "ATUIN_HISTORY_ID",
    "STARSHIP_SESSION_KEY",
    "VSCODE_IPC_HOOK",
    "VSCODE_GIT_IPC_HANDLE",
    # SSH/GPG (socket paths, not secrets)
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "GPG_AGENT_INFO",
    # Windows system variables (paths/identifiers, not secrets)
    "ALLUSERSPROFILE",
    "APPDATA",
    "COMMONPROGRAMFILES",
    "COMMONPROGRAMFILES(X86)",
    "COMPUTERNAME",
    "COMSPEC",
    "DRIVERDATA",
    "HOMEDRIVE",
    "HOMEPATH",
    "LOCALAPPDATA",
    "LOGONSERVER",
    "NUMBER_OF_PROCESSORS",
    "OS",
    "PATHEXT",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "PROCESSOR_LEVEL",
    "PROCESSOR_REVISION",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
    "PSMODULEPATH",
    "PUBLIC",
    "SESSIONNAME",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "USERDOMAIN",
    "USERDOMAIN_ROAMINGPROFILE",
    "USERPROFILE",
    "WINDIR",
    # Cloud provider identifiers (not secrets)
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_PROFILE",
    "AWS_DEFAULT_OUTPUT",
    "GOOGLE_CLOUD_PROJECT",
    "CLOUDSDK_CORE_PROJECT",
    "CLOUDSDK_CORE_ACCOUNT",
    "AZURE_RESOURCE_GROUP",
    # Kubernetes identifiers (not secrets)
    "KUBECONFIG",
    "KUBE_CONTEXT",
    "KUBE_NAMESPACE",
    "KUBERNETES_SERVICE_HOST",
    "KUBERNETES_SERVICE_PORT",
    "KUBERNETES_PORT",
    # Terraform identifiers (not secrets)
    "TF_WORKSPACE",
    "TF_CLI_CONFIG_FILE",
    "TF_DATA_DIR",
    # CI/CD identifiers (not secrets)
    "CI",
    "CI_JOB_ID",
    "CI_PIPELINE_ID",
    "GITHUB_RUN_ID",
    "GITHUB_WORKFLOW",
    "GITHUB_REPOSITORY",
    "GITHUB_ACTOR",
    "GITHUB_REF",
    "GITHUB_SHA",
    "GITHUB_EVENT_NAME",
    "GITLAB_CI",
    "GITLAB_USER_LOGIN",
    "CIRCLECI",
    "TRAVIS",
    "JENKINS_URL",
    "BUILD_NUMBER",
}

# Prefixes for environment variable names that are typically not secrets
EXCLUDED_ENV_PREFIXES = (
    "OTEL_",  # OpenTelemetry config
    "LC_",  # Locale settings
    "XDG_",  # XDG Base Directory
    "LESS",  # Less pager config
    "LS_",  # ls command config
)


class EnvironmentSecretSource(SecretSource):
    """Collects secrets from environment variables."""

    @property
    def source_type(self) -> SourceType:
        return SourceType.ENVIRONMENT_VAR

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield potential secrets from environment variables.

        Excludes common non-secret environment variables like PATH, HOME, etc.
        """
        for name, value in os.environ.items():
            upper_name = name.upper()

            # Skip excluded keys (exact match)
            if upper_name in EXCLUDED_ENV_KEYS:
                continue

            # Skip excluded prefixes
            if upper_name.startswith(EXCLUDED_ENV_PREFIXES):
                continue

            yield GatheredSecret(
                value=value,
                metadata=SecretMetadata(
                    source_type=self.source_type,
                    source_path="environment",
                    secret_name=name,
                ),
            )
