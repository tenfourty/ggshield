"""
Tests for inventory builder functions.
"""

from ggshield.verticals.machine.analyzer import AnalysisResult, AnalyzedSecret
from ggshield.verticals.machine.inventory.builder import (
    build_inventory_from_analysis,
    build_inventory_from_scan,
)
from ggshield.verticals.machine.sources import (
    GatheredSecret,
    SecretMetadata,
    SourceType,
)


def make_gathered_secret(
    value: str = "secret_value",
    source_type: SourceType = SourceType.ENVIRONMENT_VAR,
    source_path: str = "environment",
    secret_name: str = "API_KEY",
) -> GatheredSecret:
    """Create a test GatheredSecret."""
    return GatheredSecret(
        value=value,
        metadata=SecretMetadata(
            source_type=source_type,
            source_path=source_path,
            secret_name=secret_name,
        ),
    )


def make_analyzed_secret(
    value: str = "secret_value",
    source_path: str = "environment",
    secret_name: str = "API_KEY",
    detector_name: str = "generic_api_key",
    detector_display_name: str = "Generic API Key",
    validity: str = "valid",
    hmsl_leaked: bool = False,
) -> AnalyzedSecret:
    """Create a test AnalyzedSecret."""
    return AnalyzedSecret(
        gathered_secret=make_gathered_secret(
            value=value,
            source_path=source_path,
            secret_name=secret_name,
        ),
        detector_name=detector_name,
        detector_display_name=detector_display_name,
        validity=validity,
        hmsl_leaked=hmsl_leaked,
    )


class TestBuildInventoryFromAnalysis:
    """Tests for build_inventory_from_analysis function."""

    def test_groups_secrets_by_source_path(self):
        """Test that secrets are grouped by source_path into collections."""
        result = AnalysisResult(
            analyzed_secrets=[
                make_analyzed_secret(source_path="/path/one", secret_name="KEY1"),
                make_analyzed_secret(source_path="/path/one", secret_name="KEY2"),
                make_analyzed_secret(source_path="/path/two", secret_name="KEY3"),
            ],
            fetched_at="2025-01-01T00:00:00+00:00",
        )

        payload = build_inventory_from_analysis(result, "test-machine")

        assert len(payload.items) == 2
        # Find the items by resource_key
        path_one_item = next(
            (i for i in payload.items if i.resource_key == "/path/one"), None
        )
        path_two_item = next(
            (i for i in payload.items if i.resource_key == "/path/two"), None
        )

        assert path_one_item is not None
        assert len(path_one_item.secrets) == 2
        assert path_two_item is not None
        assert len(path_two_item.secrets) == 1

    def test_includes_enrichment_data(self):
        """Test that detector, validity, and leak status are included."""
        result = AnalysisResult(
            analyzed_secrets=[
                make_analyzed_secret(
                    detector_display_name="AWS Keys",
                    validity="valid",
                    hmsl_leaked=True,
                ),
            ],
            fetched_at="2025-01-01T00:00:00+00:00",
        )

        payload = build_inventory_from_analysis(result, "test-machine")

        secret = payload.items[0].secrets[0]
        assert secret.detector == "AWS Keys"
        assert secret.validity == "valid"
        assert secret.leaked is True

    def test_uses_gg_hash_and_gg_length(self):
        """Test that gg_hash and gg_length properties are used."""
        analyzed = make_analyzed_secret(value="test_secret")
        result = AnalysisResult(
            analyzed_secrets=[analyzed],
            fetched_at="2025-01-01T00:00:00+00:00",
        )

        payload = build_inventory_from_analysis(result, "test-machine")

        secret = payload.items[0].secrets[0]
        # gg_hash is 64 chars hex
        assert len(secret.hash) == 64
        # gg_length is byte length
        assert secret.length == len("test_secret".encode("utf-8"))

    def test_sets_source_name(self):
        """Test that source_name is set correctly."""
        result = AnalysisResult(
            analyzed_secrets=[make_analyzed_secret()],
            fetched_at="2025-01-01T00:00:00+00:00",
        )

        payload = build_inventory_from_analysis(result, "my-hostname")

        assert payload.source_name == "my-hostname"
        assert payload.source_id == {"account_id": "my-hostname"}

    def test_sets_environment(self):
        """Test that env is set correctly."""
        result = AnalysisResult(
            analyzed_secrets=[make_analyzed_secret()],
            fetched_at="2025-01-01T00:00:00+00:00",
        )

        payload = build_inventory_from_analysis(
            result, "test-machine", env="production"
        )

        assert payload.env == "production"

    def test_default_environment_is_development(self):
        """Test that default env is 'development'."""
        result = AnalysisResult(
            analyzed_secrets=[make_analyzed_secret()],
            fetched_at="2025-01-01T00:00:00+00:00",
        )

        payload = build_inventory_from_analysis(result, "test-machine")

        assert payload.env == "development"

    def test_uses_fetched_at_from_result(self):
        """Test that fetched_at is taken from AnalysisResult."""
        result = AnalysisResult(
            analyzed_secrets=[make_analyzed_secret()],
            fetched_at="2025-06-15T12:00:00+00:00",
        )

        payload = build_inventory_from_analysis(result, "test-machine")

        assert payload.items[0].fetched_at == "2025-06-15T12:00:00+00:00"


class TestBuildInventoryFromScan:
    """Tests for build_inventory_from_scan function."""

    def test_groups_secrets_by_source_path(self):
        """Test that secrets are grouped by source_path into collections."""
        secrets = [
            make_gathered_secret(source_path="/path/one", secret_name="KEY1"),
            make_gathered_secret(source_path="/path/one", secret_name="KEY2"),
            make_gathered_secret(source_path="/path/two", secret_name="KEY3"),
        ]

        payload = build_inventory_from_scan(secrets, "test-machine")

        assert len(payload.items) == 2

    def test_no_enrichment_data(self):
        """Test that secrets have no enrichment data (detector, validity, leaked)."""
        secrets = [make_gathered_secret()]

        payload = build_inventory_from_scan(secrets, "test-machine")

        secret = payload.items[0].secrets[0]
        assert secret.detector is None
        assert secret.validity is None
        assert secret.leaked is None

    def test_computes_hash_and_length(self):
        """Test that hash and length are computed correctly."""
        secrets = [make_gathered_secret(value="test_secret")]

        payload = build_inventory_from_scan(secrets, "test-machine")

        secret = payload.items[0].secrets[0]
        # Hash is 64 chars hex (scrypt)
        assert len(secret.hash) == 64
        # Length is byte length
        assert secret.length == len("test_secret".encode("utf-8"))

    def test_sets_source_name(self):
        """Test that source_name is set correctly."""
        secrets = [make_gathered_secret()]

        payload = build_inventory_from_scan(secrets, "my-hostname")

        assert payload.source_name == "my-hostname"
        assert payload.source_id == {"account_id": "my-hostname"}

    def test_sets_environment(self):
        """Test that env is set correctly."""
        secrets = [make_gathered_secret()]

        payload = build_inventory_from_scan(secrets, "test-machine", env="staging")

        assert payload.env == "staging"

    def test_default_environment_is_development(self):
        """Test that default env is 'development'."""
        secrets = [make_gathered_secret()]

        payload = build_inventory_from_scan(secrets, "test-machine")

        assert payload.env == "development"

    def test_uses_sub_path_from_secret_name(self):
        """Test that sub_path comes from secret_name."""
        secrets = [make_gathered_secret(secret_name="MY_API_KEY")]

        payload = build_inventory_from_scan(secrets, "test-machine")

        secret = payload.items[0].secrets[0]
        assert secret.sub_path == "MY_API_KEY"

    def test_empty_secrets_list(self):
        """Test that empty secrets list produces empty payload."""
        payload = build_inventory_from_scan([], "test-machine")

        assert len(payload.items) == 0
        assert payload.source_name == "test-machine"
