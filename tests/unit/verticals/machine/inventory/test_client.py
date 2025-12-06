"""
Tests for InventoryClient.
"""

import gzip
import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from ggshield.verticals.machine.inventory.client import InventoryClient, NHIAuthError
from ggshield.verticals.machine.inventory.models import (
    InventoryPayload,
    SecretCollectionItem,
    SecretItem,
)


def make_test_payload() -> InventoryPayload:
    """Create a test InventoryPayload."""
    return InventoryPayload(
        source_type="demo",
        source_id={"account_id": "test-machine"},
        source_name="test-machine",
        items=[
            SecretCollectionItem(
                source_type="demo",
                source_id={"account_id": "test-machine"},
                resource_key="/home/user/.env",
                secrets=[
                    SecretItem(hash="abc123", length=10, sub_path="API_KEY"),
                ],
                fetched_at="2025-01-01T00:00:00+00:00",
            ),
        ],
        env="development",
        agent_version="ggshield/1.0.0",
    )


class TestInventoryClient:
    """Tests for InventoryClient class."""

    def test_upload_sends_gzip_compressed_json(self):
        """Test that upload sends gzip-compressed JSON data."""
        client = InventoryClient(
            api_url="https://api.gitguardian.com",
            api_key="test-api-key",
            agent_version="ggshield/1.0.0",
        )
        payload = make_test_payload()

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {"raw_data_id": 12345}
            mock_post.return_value = mock_response

            client.upload(payload)

            # Verify the data was gzip compressed
            call_args = mock_post.call_args
            sent_data = call_args[1]["data"]

            # Decompress and verify it's valid JSON
            decompressed = gzip.decompress(sent_data)
            json_data = json.loads(decompressed.decode("utf-8"))

            assert "outputs" in json_data
            assert json_data["schema_version"] == "2025-12-02"

    def test_upload_sends_correct_headers(self):
        """Test that upload sends correct headers."""
        client = InventoryClient(
            api_url="https://api.gitguardian.com",
            api_key="test-api-key",
            agent_version="ggshield/1.2.3",
        )
        payload = make_test_payload()

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {"raw_data_id": 12345}
            mock_post.return_value = mock_response

            client.upload(payload)

            call_args = mock_post.call_args
            headers = call_args[1]["headers"]

            assert headers["Authorization"] == "Token test-api-key"
            assert headers["Content-Type"] == "application/json"
            assert headers["Content-Encoding"] == "gzip"
            assert headers["Gg-Scout-Version"] == "ggshield/1.2.3"
            assert headers["Gg-Scout-Platform"] == "python"

    def test_upload_calls_correct_endpoint(self):
        """Test that upload calls the correct API endpoint."""
        client = InventoryClient(
            api_url="https://api.gitguardian.com",
            api_key="test-api-key",
            agent_version="ggshield/1.0.0",
        )
        payload = make_test_payload()

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {"raw_data_id": 12345}
            mock_post.return_value = mock_response

            client.upload(payload)

            call_args = mock_post.call_args
            url = call_args[0][0]

            assert url == "https://api.gitguardian.com/v1/nhi/inventory/upload"

    def test_upload_strips_trailing_slash_from_api_url(self):
        """Test that trailing slash is stripped from api_url."""
        client = InventoryClient(
            api_url="https://api.gitguardian.com/",
            api_key="test-api-key",
            agent_version="ggshield/1.0.0",
        )
        payload = make_test_payload()

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {"raw_data_id": 12345}
            mock_post.return_value = mock_response

            client.upload(payload)

            call_args = mock_post.call_args
            url = call_args[0][0]

            assert url == "https://api.gitguardian.com/v1/nhi/inventory/upload"

    def test_upload_returns_response_json(self):
        """Test that upload returns the response JSON."""
        client = InventoryClient(
            api_url="https://api.gitguardian.com",
            api_key="test-api-key",
            agent_version="ggshield/1.0.0",
        )
        payload = make_test_payload()

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {"raw_data_id": 12345}
            mock_post.return_value = mock_response

            result = client.upload(payload)

            assert result == {"raw_data_id": 12345}

    def test_upload_raises_nhi_auth_error_on_401_unauthorized(self):
        """Test that upload raises NHIAuthError on 401 Unauthorized."""
        client = InventoryClient(
            api_url="https://api.gitguardian.com",
            api_key="invalid-key",
            agent_version="ggshield/1.0.0",
        )
        payload = make_test_payload()

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.ok = False
            mock_response.status_code = 401
            mock_post.return_value = mock_response

            with pytest.raises(NHIAuthError):
                client.upload(payload)

    def test_upload_raises_nhi_auth_error_on_403_forbidden(self):
        """Test that upload raises NHIAuthError on 403 Forbidden."""
        client = InventoryClient(
            api_url="https://api.gitguardian.com",
            api_key="test-api-key",
            agent_version="ggshield/1.0.0",
        )
        payload = make_test_payload()

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.ok = False
            mock_response.status_code = 403
            mock_post.return_value = mock_response

            with pytest.raises(NHIAuthError):
                client.upload(payload)

    def test_upload_raises_on_500_server_error(self):
        """Test that upload raises HTTPError on 500 Server Error."""
        client = InventoryClient(
            api_url="https://api.gitguardian.com",
            api_key="test-api-key",
            agent_version="ggshield/1.0.0",
        )
        payload = make_test_payload()

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.ok = False
            mock_response.status_code = 500
            mock_response.raise_for_status.side_effect = requests.HTTPError(
                "500 Server Error"
            )
            mock_post.return_value = mock_response

            with pytest.raises(requests.HTTPError):
                client.upload(payload)

    def test_ping_calls_nhi_ping_endpoint(self):
        """Test that ping calls the /nhi/ping endpoint with POST."""
        client = InventoryClient(
            api_url="https://api.gitguardian.com",
            api_key="test-api-key",
            agent_version="ggshield/1.0.0",
        )

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.content = b"{}"
            mock_response.json.return_value = {}
            mock_post.return_value = mock_response

            result = client.ping("test-machine")

            assert result == {}
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert call_args[0][0] == "https://api.gitguardian.com/v1/nhi/ping"

    def test_ping_sends_correct_payload(self):
        """Test that ping sends source identifier, permissions, and env."""
        client = InventoryClient(
            api_url="https://api.gitguardian.com",
            api_key="test-api-key",
            agent_version="ggshield/1.0.0",
        )

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.content = b"{}"
            mock_response.json.return_value = {}
            mock_post.return_value = mock_response

            client.ping("my-hostname", env="production")

            call_args = mock_post.call_args
            payload = call_args[1]["json"]
            assert len(payload) == 1
            assert payload[0]["identifier"]["type"] == "demo"
            assert payload[0]["identifier"]["source"] == "my-hostname"
            assert payload[0]["permissions"] == "read/write"
            assert payload[0]["env"] == "production"

    def test_ping_raises_nhi_auth_error_on_401(self):
        """Test that ping raises NHIAuthError on 401 Unauthorized."""
        client = InventoryClient(
            api_url="https://api.gitguardian.com",
            api_key="invalid-key",
            agent_version="ggshield/1.0.0",
        )

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.ok = False
            mock_response.status_code = 401
            mock_post.return_value = mock_response

            with pytest.raises(NHIAuthError):
                client.ping("test-machine")

    def test_ping_does_not_use_gzip_header(self):
        """Test that ping does not send gzip Content-Encoding header."""
        client = InventoryClient(
            api_url="https://api.gitguardian.com",
            api_key="test-api-key",
            agent_version="ggshield/1.0.0",
        )

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.content = b"{}"
            mock_response.json.return_value = {}
            mock_post.return_value = mock_response

            client.ping("test-machine")

            call_args = mock_post.call_args
            headers = call_args[1]["headers"]
            assert "Content-Encoding" not in headers


class TestNHIAuthError:
    """Tests for NHI authentication error handling."""

    def test_upload_raises_nhi_auth_error_on_404(self):
        """Test that upload raises NHIAuthError on 404 with helpful message."""
        client = InventoryClient(
            api_url="https://api.gitguardian.com",
            api_key="test-api-key",
            agent_version="ggshield/1.0.0",
        )
        payload = make_test_payload()

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.ok = False
            mock_response.status_code = 404
            mock_post.return_value = mock_response

            with pytest.raises(NHIAuthError) as exc_info:
                client.upload(payload)

            assert "NHI endpoint not found" in str(exc_info.value)
            assert "nhi:send-inventory" in str(exc_info.value)

    def test_upload_raises_nhi_auth_error_on_401(self):
        """Test that upload raises NHIAuthError on 401 with helpful message."""
        client = InventoryClient(
            api_url="https://api.gitguardian.com",
            api_key="test-api-key",
            agent_version="ggshield/1.0.0",
        )
        payload = make_test_payload()

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.ok = False
            mock_response.status_code = 401
            mock_post.return_value = mock_response

            with pytest.raises(NHIAuthError) as exc_info:
                client.upload(payload)

            assert "Authentication failed" in str(exc_info.value)
            assert "GITGUARDIAN_NHI_API_KEY" in str(exc_info.value)

    def test_upload_raises_nhi_auth_error_on_403(self):
        """Test that upload raises NHIAuthError on 403 with helpful message."""
        client = InventoryClient(
            api_url="https://api.gitguardian.com",
            api_key="test-api-key",
            agent_version="ggshield/1.0.0",
        )
        payload = make_test_payload()

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.ok = False
            mock_response.status_code = 403
            mock_post.return_value = mock_response

            with pytest.raises(NHIAuthError) as exc_info:
                client.upload(payload)

            assert "Permission denied" in str(exc_info.value)
            assert "nhi:send-inventory" in str(exc_info.value)

    def test_ping_raises_nhi_auth_error_on_404(self):
        """Test that ping raises NHIAuthError on 404."""
        client = InventoryClient(
            api_url="https://api.gitguardian.com",
            api_key="test-api-key",
            agent_version="ggshield/1.0.0",
        )

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.ok = False
            mock_response.status_code = 404
            mock_post.return_value = mock_response

            with pytest.raises(NHIAuthError) as exc_info:
                client.ping("test-machine")

            assert "NHI endpoint not found" in str(exc_info.value)

    def test_ping_raises_nhi_auth_error_on_401(self):
        """Test that ping raises NHIAuthError on 401."""
        client = InventoryClient(
            api_url="https://api.gitguardian.com",
            api_key="test-api-key",
            agent_version="ggshield/1.0.0",
        )

        with patch.object(client.session, "post") as mock_post:
            mock_response = MagicMock()
            mock_response.ok = False
            mock_response.status_code = 401
            mock_post.return_value = mock_response

            with pytest.raises(NHIAuthError) as exc_info:
                client.ping("test-machine")

            assert "Authentication failed" in str(exc_info.value)
