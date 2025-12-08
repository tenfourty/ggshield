"""
Google Cloud Platform Application Default Credentials source.

Scans ~/.config/gcloud/application_default_credentials.json for OAuth tokens.
On Windows, scans %APPDATA%/gcloud/application_default_credentials.json instead.
"""

import json
from pathlib import Path
from typing import Iterator, Optional

from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)
from ggshield.verticals.machine.sources.base import SecretSource
from ggshield.verticals.machine.sources.platform_paths import get_appdata, is_windows


class GcpAdcSource(SecretSource):
    """Collects secrets from GCP Application Default Credentials."""

    def __init__(self, home_dir: Optional[Path] = None):
        """
        Initialise source.

        Args:
            home_dir: Home directory to search in. Defaults to user's home.
        """
        self._home_dir = home_dir or Path.home()

    @property
    def source_type(self) -> SourceType:
        return SourceType.GCP_ADC

    def _get_adc_path(self) -> Optional[Path]:
        """Get the ADC file path based on the current platform."""
        if is_windows():
            appdata = get_appdata()
            if appdata:
                return appdata / "gcloud" / "application_default_credentials.json"
            return None
        return (
            self._home_dir
            / ".config"
            / "gcloud"
            / "application_default_credentials.json"
        )

    def gather(self) -> Iterator[GatheredSecret]:
        """
        Yield secrets from GCP ADC file.

        The file contains OAuth credentials with client_secret and refresh_token.
        """
        adc_path = self._get_adc_path()
        if adc_path is None or not adc_path.exists() or not adc_path.is_file():
            return

        try:
            content = adc_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return

        try:
            config = json.loads(content)
        except json.JSONDecodeError:
            return

        # Extract sensitive fields
        secret_fields = ["client_secret", "refresh_token"]
        for field in secret_fields:
            value = config.get(field)
            if value and isinstance(value, str):
                yield GatheredSecret(
                    value=value,
                    metadata=SecretMetadata(
                        source_type=self.source_type,
                        source_path=str(adc_path),
                        secret_name=field,
                    ),
                )
