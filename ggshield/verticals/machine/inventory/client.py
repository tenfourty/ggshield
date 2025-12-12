"""
Client for GitGuardian inventory API.
"""

import gzip
from typing import Any, Dict

import requests

from ggshield.verticals.machine.inventory.models import InventoryPayload


class NHIAuthError(Exception):
    """Raised when NHI authentication or authorization fails."""

    pass


class InventoryClient:
    """Client for GitGuardian Inventory Management API."""

    def __init__(self, api_url: str, api_key: str, agent_version: str):
        """
        Initialize the inventory client.

        Args:
            api_url: GitGuardian API base URL
            api_key: GitGuardian API key (should be a service account with nhi:send-inventory scope)
            agent_version: Version string for Gg-Scout-Version header
        """
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.agent_version = agent_version
        self.session = requests.Session()

    def _get_headers(self, include_gzip: bool = True) -> Dict[str, str]:
        """Get standard headers for inventory API."""
        headers = {
            "Authorization": f"Token {self.api_key}",
            "Content-Type": "application/json",
            "Gg-Scout-Version": self.agent_version,
            "Gg-Scout-Platform": "python",
        }
        if include_gzip:
            headers["Content-Encoding"] = "gzip"
        return headers

    def _handle_response_error(self, response: requests.Response) -> None:
        """
        Handle HTTP errors with helpful NHI-specific messages.

        Raises:
            NHIAuthError: For 404, 401, 403 errors with helpful messages
            requests.HTTPError: For other HTTP errors
        """
        if response.status_code == 404:
            raise NHIAuthError(
                "NHI endpoint not found. Ensure your GitGuardian instance "
                "has NHI features enabled and your API key has the "
                "'nhi:send-inventory' scope.\n"
                "See: https://docs.gitguardian.com/ggscout-docs/configure-ggscout"
            )
        elif response.status_code == 401:
            raise NHIAuthError(
                "Authentication failed. Check that GITGUARDIAN_NHI_API_KEY "
                "is set to a service account with 'nhi:send-inventory' scope."
            )
        elif response.status_code == 403:
            raise NHIAuthError(
                "Permission denied. Your API key may not have the required "
                "'nhi:send-inventory' scope."
            )
        response.raise_for_status()

    def upload(self, payload: InventoryPayload) -> Dict[str, Any]:
        """
        Upload inventory to GitGuardian (gzip compressed).

        Args:
            payload: InventoryPayload to upload

        Returns:
            API response as dict (typically {"raw_data_id": int})

        Raises:
            NHIAuthError: On authentication/authorization errors
            requests.HTTPError: On other API errors
        """
        json_data = payload.to_json().encode("utf-8")
        compressed = gzip.compress(json_data)

        response = self.session.post(
            f"{self.api_url}/v1/nhi/inventory/upload",
            data=compressed,
            headers=self._get_headers(),
        )

        if not response.ok:
            self._handle_response_error(response)

        return response.json()

    def ping(self, source_name: str, env: str = "development") -> dict:
        """
        Test connectivity and send source information to GitGuardian.

        This mirrors the ggscout ping behavior - it sends source info to
        the /nhi/ping endpoint and validates the response.

        Args:
            source_name: Source name (hostname)
            env: Environment (development, staging, production, etc.)

        Returns:
            Response dict from the API

        Raises:
            NHIAuthError: On authentication/authorization errors
            requests.HTTPError: On other API errors
        """
        payload = [
            {
                "identifier": {
                    "type": "demo",
                    "source": source_name,
                },
                "permissions": "read/write",
                "env": env,
            }
        ]

        response = self.session.post(
            f"{self.api_url}/v1/nhi/ping",
            json=payload,
            headers=self._get_headers(include_gzip=False),
        )

        if not response.ok:
            self._handle_response_error(response)

        # Check x-app-version header if present (for version compatibility)
        app_version = response.headers.get("x-app-version")
        if app_version:
            # Log version info (could add version check later)
            pass

        return response.json() if response.content else {}
