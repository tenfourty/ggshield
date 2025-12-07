"""
Tests for GCP Application Default Credentials source.
"""

import json
from pathlib import Path

from ggshield.verticals.machine.sources import SourceType
from ggshield.verticals.machine.sources.gcp_adc import GcpAdcSource


class TestGcpAdcSource:
    """Tests for GcpAdcSource."""

    def test_source_type(self):
        """
        GIVEN a GcpAdcSource
        WHEN accessing source_type
        THEN it returns GCP_ADC
        """
        source = GcpAdcSource()
        assert source.source_type == SourceType.GCP_ADC

    def test_gather_with_client_secret(self, tmp_path: Path):
        """
        GIVEN an ADC file with client_secret
        WHEN gathering secrets
        THEN yields the client_secret
        """
        gcloud_dir = tmp_path / ".config" / "gcloud"
        gcloud_dir.mkdir(parents=True)
        adc_content = {
            "client_id": "123456789.apps.googleusercontent.com",
            "client_secret": "GOCSPX-secret123456789",
            "refresh_token": "1//refresh_token_here",
            "type": "authorized_user",
        }
        (gcloud_dir / "application_default_credentials.json").write_text(
            json.dumps(adc_content)
        )

        source = GcpAdcSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 2
        values = {s.value for s in secrets}
        assert "GOCSPX-secret123456789" in values
        assert "1//refresh_token_here" in values
        assert all(s.metadata.source_type == SourceType.GCP_ADC for s in secrets)

    def test_gather_with_refresh_token_only(self, tmp_path: Path):
        """
        GIVEN an ADC file with only refresh_token
        WHEN gathering secrets
        THEN yields the refresh_token
        """
        gcloud_dir = tmp_path / ".config" / "gcloud"
        gcloud_dir.mkdir(parents=True)
        adc_content = {
            "client_id": "123456789.apps.googleusercontent.com",
            "refresh_token": "1//0refresh_token",
            "type": "authorized_user",
        }
        (gcloud_dir / "application_default_credentials.json").write_text(
            json.dumps(adc_content)
        )

        source = GcpAdcSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 1
        assert secrets[0].value == "1//0refresh_token"
        assert secrets[0].metadata.secret_name == "refresh_token"

    def test_gather_no_adc_file(self, tmp_path: Path):
        """
        GIVEN no ADC file exists
        WHEN gathering secrets
        THEN yields nothing
        """
        source = GcpAdcSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_empty_adc_file(self, tmp_path: Path):
        """
        GIVEN an empty ADC file
        WHEN gathering secrets
        THEN yields nothing
        """
        gcloud_dir = tmp_path / ".config" / "gcloud"
        gcloud_dir.mkdir(parents=True)
        (gcloud_dir / "application_default_credentials.json").write_text("{}")

        source = GcpAdcSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0

    def test_gather_invalid_json(self, tmp_path: Path):
        """
        GIVEN an ADC file with invalid JSON
        WHEN gathering secrets
        THEN yields nothing
        """
        gcloud_dir = tmp_path / ".config" / "gcloud"
        gcloud_dir.mkdir(parents=True)
        (gcloud_dir / "application_default_credentials.json").write_text(
            "not valid json"
        )

        source = GcpAdcSource(home_dir=tmp_path)
        secrets = list(source.gather())

        assert len(secrets) == 0
