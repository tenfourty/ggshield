"""
File matcher protocol and implementations for unified filesystem scanning.

This module provides a pluggable architecture for detecting different file types
during a single filesystem traversal.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Pattern, Protocol, Set

from ggshield.utils.files import is_path_excluded
from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)


class FileMatcher(Protocol):
    """
    Protocol for pluggable file type detectors.

    Implementations identify files of interest during filesystem traversal
    and extract secrets from matched files.
    """

    @property
    def source_type(self) -> SourceType:
        """The source type this matcher identifies."""
        ...

    @property
    def allowed_dot_directories(self) -> Set[str]:
        """
        Dot directories that should NOT be pruned for this matcher.

        The unified walker computes the union of all matchers' allowed
        directories, ensuring no matcher misses files in directories it needs.
        """
        ...

    def matches_filename(self, filename: str) -> bool:
        """
        Quick string-based check if filename matches (no Path, no I/O).

        PERFORMANCE: This is called for every file (~2M times on typical home dir).
        Must be fast - string operations only, no object creation.

        Args:
            filename: Just the filename (e.g., ".env", "id_rsa", "server.pem")

        Returns:
            True if this file should be processed by this matcher
        """
        ...

    def extract_secrets(
        self,
        file_path: Path,
        exclusion_regexes: Set[Pattern[str]],
    ) -> Iterator[GatheredSecret]:
        """
        Read file and extract secrets.

        Called only for files that matched via matches_filename().
        Should handle exclusion checking, file reading errors, and content validation.

        Args:
            file_path: Full path to the matched file
            exclusion_regexes: Patterns to exclude (from config)

        Yields:
            GatheredSecret instances found in the file
        """
        ...


# Regex to extract KEY=value assignments from .env files
_ASSIGNMENT_REGEX = re.compile(
    r"""
    ^\s*
    (?P<name>[a-zA-Z_]\w*)
    \s*=\s*
    (?P<value>.{1,5000})
""",
    re.VERBOSE,
)

# Common placeholder values that are not real secrets (case-insensitive)
_PLACEHOLDER_VALUES = frozenset(
    {
        "test",
        "testing",
        "changeme",
        "change_me",
        "placeholder",
        "example",
        "xxx",
        "yyy",
        "zzz",
        "todo",
        "fixme",
        "none",
        "null",
        "undefined",
        "secret",
        "password",
        "your_api_key",
        "your_secret",
        "your_token",
        "your_key",
        "api_key",
        "api_secret",
        "my_api_key",
        "my_secret",
        "insert_here",
        "replace_me",
        "update_me",
    }
)

# Substrings that indicate a placeholder (case-insensitive)
_PLACEHOLDER_SUBSTRINGS = (
    "fill-me",
    "fill_me",
    "your-",
    "your_",
    "<your",
    "replace-",
    "replace_",
    "insert-",
    "insert_",
    "enter-",
    "enter_",
)


def _is_placeholder_value(value: str) -> bool:
    """Check if value looks like a placeholder, not a real secret."""
    lower = value.lower()

    # Exact match against known placeholders
    if lower in _PLACEHOLDER_VALUES:
        return True

    # Check for placeholder substrings
    for pattern in _PLACEHOLDER_SUBSTRINGS:
        if pattern in lower:
            return True

    # Check for unresolved variable references like ${VAR} or $VAR
    if value.startswith("${") or (value.startswith("$") and not value.startswith("$$")):
        return True

    return False


# Variable name suffixes that typically indicate non-secret config values
_NON_SECRET_NAME_SUFFIXES = (
    "_URL",
    "_URI",
    "_ADDR",
    "_ADDRESS",
    "_HOST",
    "_HOSTNAME",
    "_PORT",
    "_REGION",
    "_ZONE",
    "_INSTANCE",
    "_SCHEMA",
    "_DATABASE",
    "_WAREHOUSE",
    "_ROLE",
    "_USER",
    "_USERNAME",
    "_ACCOUNT",
    "_EMAIL",
    "_LEVEL",
    "_MODE",
    "_ENV",
    "_ENVIRONMENT",
    "_PATH",
    "_DIR",
    "_DIRECTORY",
    "_ROOT",
    "_HOME",
    "_PREFIX",
    "_IDENTITY",
)

# Exact variable names that are typically not secrets
_NON_SECRET_NAMES = frozenset(
    {
        "HOST",
        "PORT",
        "LOG_LEVEL",
        "DEBUG",
        "KUBECONFIG",
        "NODE_ENV",
        "RAILS_ENV",
        "FLASK_ENV",
        "ENVIRONMENT",
    }
)


def _is_non_secret_name(name: str) -> bool:
    """Check if variable name indicates a non-secret config value."""
    upper = name.upper()

    if upper in _NON_SECRET_NAMES:
        return True

    return upper.endswith(_NON_SECRET_NAME_SUFFIXES)


# Value patterns that indicate non-secret configuration
_NON_SECRET_VALUE_PREFIXES = (
    "http://",
    "https://",
    "ftp://",
    "file://",
    "ssh://",
    "git://",
    "postgres://",
    "mysql://",
    "mongodb://",
    "redis://",
    "amqp://",
)

_NON_SECRET_VALUES = frozenset(
    {
        # Log levels
        "debug",
        "info",
        "warn",
        "warning",
        "error",
        "fatal",
        "trace",
        "off",
        # Boolean-ish
        "true",
        "false",
        "yes",
        "no",
        "on",
        "off",
        "enabled",
        "disabled",
        # Environments
        "development",
        "production",
        "staging",
        "test",
        "local",
        # Common hostnames
        "localhost",
    }
)


def _is_non_secret_value(value: str) -> bool:
    """Check if value looks like non-secret configuration."""
    lower = value.lower()

    # Check exact matches
    if lower in _NON_SECRET_VALUES:
        return True

    # Check URL prefixes
    if lower.startswith(_NON_SECRET_VALUE_PREFIXES):
        return True

    # Check for IP addresses (simple pattern)
    if _looks_like_ip_address(value):
        return True

    # Check for email addresses (likely usernames, not secrets)
    if "@" in value and "." in value.split("@")[-1]:
        return True

    # Check for file paths (start with / or ./ or contain common path separators)
    if value.startswith(("/", "./", "../")) or value.startswith("."):
        # But not if it looks like a secret (e.g., ./secret or .env)
        if "/" in value or value.count(".") > 1:
            return True

    # Check for AWS regions (e.g., us-east-1, eu-west-3)
    if _looks_like_aws_region(value):
        return True

    return False


def _looks_like_ip_address(value: str) -> bool:
    """Check if value looks like an IP address."""
    parts = value.split(".")
    if len(parts) == 4:
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts if p.isdigit())
    return False


def _looks_like_aws_region(value: str) -> bool:
    """Check if value looks like an AWS region code."""
    # Pattern: xx-xxxx-N (e.g., us-east-1, eu-west-3, ap-southeast-2)
    parts = value.split("-")
    if len(parts) == 3 and len(parts[0]) == 2 and parts[2].isdigit():
        return True
    return False


@dataclass
class EnvFileMatcher:
    """
    Matcher for .env* files.

    Identifies environment configuration files and extracts KEY=value pairs.
    """

    min_chars: int = 5

    # Directories containing .env files we want to scan
    ALLOWED_DOT_DIRECTORIES: Set[str] = field(
        default_factory=lambda: {".env", ".aws", ".config"}
    )

    @property
    def source_type(self) -> SourceType:
        return SourceType.ENV_FILE

    @property
    def allowed_dot_directories(self) -> Set[str]:
        return self.ALLOWED_DOT_DIRECTORIES

    # Private key extensions to exclude (let PrivateKeyMatcher handle these)
    _PRIVATE_KEY_EXTENSIONS = {".key", ".pem", ".p12", ".pfx", ".gpg", ".asc"}

    def matches_filename(self, filename: str) -> bool:
        """
        Check if filename is a .env file (but not an example or private key).

        PERF: String operations only - no Path creation.
        """
        if not filename.startswith(".env"):
            return False
        # Skip example files
        lower = filename.lower()
        if "example" in lower or "sample" in lower or "template" in lower:
            return False
        # Skip files with private key extensions (let PrivateKeyMatcher handle them)
        dot_pos = lower.rfind(".")
        if dot_pos > 0:  # Has extension after first character
            suffix = lower[dot_pos:]
            if suffix in self._PRIVATE_KEY_EXTENSIONS:
                return False
        return True

    def extract_secrets(
        self,
        file_path: Path,
        exclusion_regexes: Set[Pattern[str]],
    ) -> Iterator[GatheredSecret]:
        """Extract KEY=value pairs from a .env file."""
        # Check exclusion patterns
        if is_path_excluded(file_path, exclusion_regexes):
            return

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        for line in content.splitlines():
            match = _ASSIGNMENT_REGEX.match(line)
            if not match:
                continue

            name = match.group("name")
            value = match.group("value").strip()

            # Handle inline comments
            if "#" in value:
                value = value.split("#")[0].strip()

            # Remove quotes
            value = _remove_quotes(value)

            # Skip empty or too short values
            if len(value) < self.min_chars:
                continue

            # Skip placeholder values
            if _is_placeholder_value(value):
                continue

            # Skip non-secret variable names (e.g., *_URL, *_HOST, *_REGION)
            if _is_non_secret_name(name):
                continue

            # Skip non-secret values (e.g., URLs, IPs, file paths)
            if _is_non_secret_value(value):
                continue

            yield GatheredSecret(
                value=value,
                metadata=SecretMetadata(
                    source_type=self.source_type,
                    source_path=str(file_path),
                    secret_name=name,
                ),
            )


# Private key detection constants
_PRIVATE_KEY_FILENAMES = {
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_xmss",
    "private_key",
    "privkey",
}

_PRIVATE_KEY_EXTENSIONS = {
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".gpg",
    ".asc",
}

# Maximum file size for private keys (10KB) - real keys are small
_MAX_KEY_FILE_SIZE = 10 * 1024

# PEM markers that indicate a PRIVATE key (not public certs)
# These are specific markers - we don't use generic "-----BEGIN" to avoid
# matching public certificates like "-----BEGIN CERTIFICATE-----"
_PRIVATE_KEY_MARKERS = (
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "PuTTY-User-Key-File",
)


@dataclass
class PrivateKeyMatcher:
    """
    Matcher for private key files.

    Identifies SSH keys, SSL certificates, and other cryptographic private keys
    by filename patterns and content validation.
    """

    # Paths already processed (e.g., from well-known locations fast-path)
    seen_paths: Set[Path] = field(default_factory=set)

    # Directories containing private keys we want to scan
    ALLOWED_DOT_DIRECTORIES: Set[str] = field(
        default_factory=lambda: {".ssh", ".gnupg", ".ssl", ".certs", ".aws", ".config"}
    )

    @property
    def source_type(self) -> SourceType:
        return SourceType.PRIVATE_KEY

    @property
    def allowed_dot_directories(self) -> Set[str]:
        return self.ALLOWED_DOT_DIRECTORIES

    def matches_filename(self, filename: str) -> bool:
        """
        Check if filename looks like a private key file.

        PERF: String operations only - no Path creation.
        """
        lower = filename.lower()

        # Check by exact filename
        if lower in _PRIVATE_KEY_FILENAMES:
            return True

        # Check by extension (need to find the suffix in the string)
        dot_pos = filename.rfind(".")
        if dot_pos != -1:
            suffix = filename[dot_pos:].lower()
            if suffix in _PRIVATE_KEY_EXTENSIONS:
                return True

        # Check for common key filename patterns
        if "private" in lower and "key" in lower:
            return True

        return False

    def extract_secrets(
        self,
        file_path: Path,
        exclusion_regexes: Set[Pattern[str]],
    ) -> Iterator[GatheredSecret]:
        """Extract private key content from a file."""
        # Skip if already processed (e.g., from well-known locations scan)
        if file_path in self.seen_paths:
            return

        # Check exclusion patterns
        if is_path_excluded(file_path, exclusion_regexes):
            return

        try:
            # Check file size first (private keys are small)
            stat = file_path.stat()
            if stat.st_size > _MAX_KEY_FILE_SIZE:
                return

            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        # Skip empty files
        if not content.strip():
            return

        # Verify it looks like a key file (has PEM markers)
        if not _looks_like_key_content(content):
            return

        # Mark as seen to avoid duplicates
        self.seen_paths.add(file_path)

        yield GatheredSecret(
            value=content.strip(),
            metadata=SecretMetadata(
                source_type=self.source_type,
                source_path=str(file_path),
                secret_name=file_path.name,
            ),
        )


def _remove_quotes(value: str) -> str:
    """Remove surrounding quotes from a value."""
    if len(value) > 1 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _looks_like_key_content(content: str) -> bool:
    """Check if content contains a private key (not just a public certificate)."""
    return any(marker in content for marker in _PRIVATE_KEY_MARKERS)


# Generic credential file names (exact matches, case-insensitive)
# These are common names for files that store authentication tokens/secrets
_GENERIC_CREDENTIAL_FILENAMES = frozenset(
    {
        # Session/auth tokens
        "session",
        "token",
        "tokens",
        "auth_token",
        "access_token",
        "refresh_token",
        "bearer_token",
        # API keys
        "api_key",
        "apikey",
        "api-key",
        # Credentials
        "credentials",
        "creds",
        "secret",
        "secrets",
        # Encryption keys (non-PEM format)
        "key",
        "master_key",
        "encryption_key",
        # OAuth
        "oauth",
        "oauth_token",
        # Generic auth
        "auth.json",
        "auth.yaml",
        "auth.yml",
        "credentials.json",
        "credentials.yaml",
        "credentials.yml",
        "secrets.json",
        "secrets.yaml",
        "secrets.yml",
    }
)

# Directories where generic credential files are commonly found
_GENERIC_CREDENTIAL_DIRECTORIES = frozenset(
    {
        ".local/share",  # XDG data directory (atuin, etc.)
        ".config",  # XDG config directory
        ".cache",  # Sometimes has tokens
    }
)

# Directories to exclude from generic credential scanning (too many false positives)
_GENERIC_CREDENTIAL_EXCLUDED_DIRS = frozenset(
    {
        "/containers/storage/",  # Container overlays have system files
        "/docker/",  # Docker storage
        "/buildx_buildkit",  # Buildkit cache
        "/overlay/",  # Container overlay filesystems
        "/snapshots/",  # Container snapshots
    }
)

# Maximum file size for generic credential files (64KB - most tokens are small)
_MAX_CREDENTIAL_FILE_SIZE = 64 * 1024

# Minimum content length to consider (avoid empty or trivial files)
_MIN_CREDENTIAL_LENGTH = 10


def _looks_like_credential_content(content: str) -> bool:
    """
    Check if content looks like it could be a credential/token.

    Simple heuristics:
    - Not empty
    - Not obviously a config/text file (no common config markers)
    - Contains alphanumeric content (tokens are usually base64/hex)
    """
    content = content.strip()

    # Too short
    if len(content) < _MIN_CREDENTIAL_LENGTH:
        return False

    # Skip if it looks like a config file or script
    config_markers = (
        "<?xml",
        "<!DOCTYPE",
        "<html",
        "#!/",
        "[",  # INI section
        "{",  # JSON (might be credentials.json, handle separately)
        "#",  # Comments
    )
    first_char = content[0] if content else ""
    if first_char in ("[", "#", "<", "!"):
        # Allow JSON files - they might contain tokens
        if not first_char == "{":
            return False

    # If it's mostly alphanumeric/base64 chars, it's likely a token
    # Allow common token characters: alphanumeric, +, /, =, -, _
    token_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=-_.")
    content_chars = set(content.replace("\n", "").replace("\r", ""))

    # If >80% of unique chars are token-like, consider it a credential
    if len(content_chars) > 0:
        token_ratio = len(content_chars & token_chars) / len(content_chars)
        if token_ratio > 0.8:
            return True

    return False


@dataclass
class GenericCredentialMatcher:
    """
    Matcher for generic credential/token files.

    Identifies files that commonly store authentication tokens, API keys,
    or session credentials based on filename patterns. This catches
    credentials from tools that don't have specific matchers (e.g., atuin,
    various CLI tools that store tokens in ~/.local/share/).
    """

    min_chars: int = 10

    # Paths already processed
    seen_paths: Set[Path] = field(default_factory=set)

    # Directories we want to scan for credential files
    ALLOWED_DOT_DIRECTORIES: Set[str] = field(
        default_factory=lambda: {".local", ".config", ".cache"}
    )

    @property
    def source_type(self) -> SourceType:
        return SourceType.GENERIC_CREDENTIAL

    @property
    def allowed_dot_directories(self) -> Set[str]:
        return self.ALLOWED_DOT_DIRECTORIES

    def matches_filename(self, filename: str) -> bool:
        """
        Check if filename looks like a credential file.

        PERF: String operations only - no Path creation.
        """
        lower = filename.lower()
        return lower in _GENERIC_CREDENTIAL_FILENAMES

    def extract_secrets(
        self,
        file_path: Path,
        exclusion_regexes: Set[Pattern[str]],
    ) -> Iterator[GatheredSecret]:
        """Extract credential content from a file."""
        # Skip if already processed
        if file_path in self.seen_paths:
            return

        # Check exclusion patterns
        if is_path_excluded(file_path, exclusion_regexes):
            return

        # Only scan files in expected locations to reduce false positives
        path_str = str(file_path)
        in_credential_location = any(
            f"/{d}/" in path_str for d in _GENERIC_CREDENTIAL_DIRECTORIES
        )
        if not in_credential_location:
            return

        # Skip container/overlay directories (too many system file false positives)
        if any(excl in path_str for excl in _GENERIC_CREDENTIAL_EXCLUDED_DIRS):
            return

        try:
            # Check file size first
            stat = file_path.stat()
            if stat.st_size > _MAX_CREDENTIAL_FILE_SIZE:
                return
            if stat.st_size < _MIN_CREDENTIAL_LENGTH:
                return

            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        # Skip empty files
        content = content.strip()
        if not content:
            return

        # Validate content looks like a credential
        if not _looks_like_credential_content(content):
            return

        # Mark as seen to avoid duplicates
        self.seen_paths.add(file_path)

        yield GatheredSecret(
            value=content,
            metadata=SecretMetadata(
                source_type=self.source_type,
                source_path=str(file_path),
                secret_name=file_path.name,
            ),
        )
