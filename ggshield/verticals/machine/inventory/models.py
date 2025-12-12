"""
Data models for GitGuardian inventory uploads.
"""

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# Schema version for inventory API
SCHEMA_VERSION = "2025-12-02"


@dataclass
class SecretItem:
    """A single secret for inventory upload."""

    hash: str
    length: int
    sub_path: str
    # Enrichment from analyze (optional)
    detector: Optional[str] = None
    validity: Optional[str] = None
    leaked: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "kind": {
                "type": "string",
                "raw": {"hash": self.hash, "length": self.length},
            },
            "sub_path": self.sub_path,
        }


@dataclass
class SecretCollectionItem:
    """A collection of secrets from a single source location."""

    source_type: str
    source_id: Dict[str, Any]
    resource_key: str
    secrets: List[SecretItem]
    fetched_at: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        # Build tags from first secret's enrichment (all secrets in collection share source)
        tags: Dict[str, str] = {}
        if self.secrets and self.secrets[0].detector:
            tags["detector"] = self.secrets[0].detector
        if self.secrets and self.secrets[0].validity:
            tags["validity"] = self.secrets[0].validity
        if self.secrets and self.secrets[0].leaked is not None:
            tags["leaked"] = str(self.secrets[0].leaked).lower()

        return {
            "type": "secretcollection",
            "id": {
                "type": self.source_type,
                "source": self.source_id,
                "resource": {"Key": {"key": self.resource_key}},
                "version": "latest",
            },
            "kind": {
                "type": "static",
                "secrets": [s.to_dict() for s in self.secrets],
                "metadata": {
                    "fetched_at": self.fetched_at,
                    "is_latest_version": True,
                    "labels": ["ggshield-machine"],
                    "tags": tags,
                },
            },
        }


@dataclass
class InventoryPayload:
    """Complete inventory upload payload."""

    source_type: str
    source_id: Dict[str, Any]
    source_name: str
    items: List[SecretCollectionItem]
    env: Optional[str]
    agent_version: str

    def to_json(self) -> str:
        """Convert to JSON string for API upload."""
        output: Dict[str, Any] = {
            "source": {
                "type": self.source_type,
                "source": self.source_id,
                "name": self.source_name,
            },
            "items": [item.to_dict() for item in self.items],
            "edges": [],
        }
        if self.env:
            output["env"] = self.env

        return json.dumps(
            {
                "outputs": [output],
                "collected_on": datetime.now(timezone.utc).isoformat(),
                "schema_version": SCHEMA_VERSION,
                "agent_version": self.agent_version,
            }
        )
