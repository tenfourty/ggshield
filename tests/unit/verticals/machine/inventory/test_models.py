"""
Tests for inventory data models.
"""

import json
from datetime import datetime

from ggshield.verticals.machine.inventory.models import (
    SCHEMA_VERSION,
    InventoryPayload,
    SecretCollectionItem,
    SecretItem,
)


class TestSecretItem:
    """Tests for SecretItem dataclass."""

    def test_to_dict_basic_structure(self):
        """Test SecretItem.to_dict() returns correct structure."""
        item = SecretItem(
            hash="abc123def456",
            length=12,
            sub_path="API_KEY",
        )
        result = item.to_dict()

        assert result == {
            "kind": {"type": "string", "raw": {"hash": "abc123def456", "length": 12}},
            "sub_path": "API_KEY",
        }

    def test_to_dict_with_enrichment_fields(self):
        """Test SecretItem stores enrichment fields (used by parent for tags)."""
        item = SecretItem(
            hash="abc123def456",
            length=12,
            sub_path="API_KEY",
            detector="AWS Keys",
            validity="valid",
            leaked=True,
        )
        # Enrichment fields are stored but not included in to_dict()
        # They're used by SecretCollectionItem for tags
        result = item.to_dict()

        assert result["kind"]["raw"]["hash"] == "abc123def456"
        assert item.detector == "AWS Keys"
        assert item.validity == "valid"
        assert item.leaked is True


class TestSecretCollectionItem:
    """Tests for SecretCollectionItem dataclass."""

    def test_to_dict_basic_structure(self):
        """Test SecretCollectionItem.to_dict() returns correct structure."""
        collection = SecretCollectionItem(
            source_type="demo",
            source_id={"account_id": "test-machine"},
            resource_key="/home/user/.env",
            secrets=[
                SecretItem(hash="abc123", length=10, sub_path="API_KEY"),
            ],
            fetched_at="2025-01-01T00:00:00+00:00",
        )
        result = collection.to_dict()

        assert result["type"] == "secretcollection"
        assert result["id"]["type"] == "demo"
        assert result["id"]["source"] == {"account_id": "test-machine"}
        assert result["id"]["resource"] == {"Key": {"key": "/home/user/.env"}}
        assert result["id"]["version"] == "latest"
        assert result["kind"]["type"] == "static"
        assert len(result["kind"]["secrets"]) == 1
        assert result["kind"]["metadata"]["fetched_at"] == "2025-01-01T00:00:00+00:00"
        assert result["kind"]["metadata"]["is_latest_version"] is True
        assert "ggshield-machine" in result["kind"]["metadata"]["labels"]

    def test_to_dict_with_enrichment_tags(self):
        """Test SecretCollectionItem includes enrichment tags from first secret."""
        collection = SecretCollectionItem(
            source_type="demo",
            source_id={"account_id": "test-machine"},
            resource_key="/home/user/.env",
            secrets=[
                SecretItem(
                    hash="abc123",
                    length=10,
                    sub_path="API_KEY",
                    detector="AWS Keys",
                    validity="valid",
                    leaked=True,
                ),
            ],
            fetched_at="2025-01-01T00:00:00+00:00",
        )
        result = collection.to_dict()

        tags = result["kind"]["metadata"]["tags"]
        assert tags["detector"] == "AWS Keys"
        assert tags["validity"] == "valid"
        assert tags["leaked"] == "true"

    def test_to_dict_without_enrichment_tags(self):
        """Test SecretCollectionItem has empty tags when no enrichment."""
        collection = SecretCollectionItem(
            source_type="demo",
            source_id={"account_id": "test-machine"},
            resource_key="/home/user/.env",
            secrets=[
                SecretItem(hash="abc123", length=10, sub_path="API_KEY"),
            ],
            fetched_at="2025-01-01T00:00:00+00:00",
        )
        result = collection.to_dict()

        tags = result["kind"]["metadata"]["tags"]
        assert tags == {}

    def test_to_dict_leaked_false_tag(self):
        """Test leaked=False is serialized as 'false' string."""
        collection = SecretCollectionItem(
            source_type="demo",
            source_id={"account_id": "test-machine"},
            resource_key="/home/user/.env",
            secrets=[
                SecretItem(
                    hash="abc123",
                    length=10,
                    sub_path="API_KEY",
                    leaked=False,
                ),
            ],
            fetched_at="2025-01-01T00:00:00+00:00",
        )
        result = collection.to_dict()

        tags = result["kind"]["metadata"]["tags"]
        assert tags["leaked"] == "false"


class TestInventoryPayload:
    """Tests for InventoryPayload dataclass."""

    def test_to_json_structure(self):
        """Test InventoryPayload.to_json() returns valid JSON with correct structure."""
        payload = InventoryPayload(
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
        json_str = payload.to_json()
        data = json.loads(json_str)

        assert "outputs" in data
        assert len(data["outputs"]) == 1
        assert data["outputs"][0]["source"]["type"] == "demo"
        assert data["outputs"][0]["source"]["name"] == "test-machine"
        assert data["outputs"][0]["env"] == "development"
        assert data["outputs"][0]["edges"] == []
        assert len(data["outputs"][0]["items"]) == 1

    def test_to_json_schema_version(self):
        """Test InventoryPayload includes correct schema version."""
        payload = InventoryPayload(
            source_type="demo",
            source_id={"account_id": "test-machine"},
            source_name="test-machine",
            items=[],
            env="development",
            agent_version="ggshield/1.0.0",
        )
        json_str = payload.to_json()
        data = json.loads(json_str)

        assert data["schema_version"] == SCHEMA_VERSION
        assert data["schema_version"] == "2025-12-02"

    def test_to_json_agent_version(self):
        """Test InventoryPayload includes agent version."""
        payload = InventoryPayload(
            source_type="demo",
            source_id={"account_id": "test-machine"},
            source_name="test-machine",
            items=[],
            env="development",
            agent_version="ggshield/1.2.3",
        )
        json_str = payload.to_json()
        data = json.loads(json_str)

        assert data["agent_version"] == "ggshield/1.2.3"

    def test_to_json_collected_on_is_iso_timestamp(self):
        """Test InventoryPayload includes ISO timestamp for collected_on."""
        payload = InventoryPayload(
            source_type="demo",
            source_id={"account_id": "test-machine"},
            source_name="test-machine",
            items=[],
            env="development",
            agent_version="ggshield/1.0.0",
        )
        json_str = payload.to_json()
        data = json.loads(json_str)

        collected_on = data["collected_on"]
        assert "T" in collected_on  # ISO format
        # Should be parseable as datetime
        datetime.fromisoformat(collected_on.replace("Z", "+00:00"))

    def test_to_json_env_omitted_when_none(self):
        """Test env field is omitted when None."""
        payload = InventoryPayload(
            source_type="demo",
            source_id={"account_id": "test-machine"},
            source_name="test-machine",
            items=[],
            env=None,
            agent_version="ggshield/1.0.0",
        )
        json_str = payload.to_json()
        data = json.loads(json_str)

        assert "env" not in data["outputs"][0]

    def test_to_json_multiple_items(self):
        """Test InventoryPayload handles multiple items."""
        payload = InventoryPayload(
            source_type="demo",
            source_id={"account_id": "test-machine"},
            source_name="test-machine",
            items=[
                SecretCollectionItem(
                    source_type="demo",
                    source_id={"account_id": "test-machine"},
                    resource_key="/path/one",
                    secrets=[SecretItem(hash="hash1", length=10, sub_path="KEY1")],
                    fetched_at="2025-01-01T00:00:00+00:00",
                ),
                SecretCollectionItem(
                    source_type="demo",
                    source_id={"account_id": "test-machine"},
                    resource_key="/path/two",
                    secrets=[SecretItem(hash="hash2", length=20, sub_path="KEY2")],
                    fetched_at="2025-01-01T00:00:00+00:00",
                ),
            ],
            env="production",
            agent_version="ggshield/1.0.0",
        )
        json_str = payload.to_json()
        data = json.loads(json_str)

        assert len(data["outputs"][0]["items"]) == 2
