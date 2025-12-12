"""
Builder functions for creating inventory payloads.
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

from ggshield import __version__
from ggshield.verticals.machine.analyzer import AnalysisResult, AnalyzedSecret
from ggshield.verticals.machine.inventory.models import (
    InventoryPayload,
    SecretCollectionItem,
    SecretItem,
)
from ggshield.verticals.machine.sources import GatheredSecret


def build_inventory_from_analysis(
    result: AnalysisResult,
    source_name: str,
    env: Optional[str] = "development",
) -> InventoryPayload:
    """
    Transform AnalysisResult into inventory payload with enrichment.

    Includes detector, validity, and leak status in metadata tags.

    Args:
        result: Analysis result containing analyzed secrets
        source_name: Machine hostname or custom source name
        env: Environment classification (default: development)

    Returns:
        InventoryPayload ready for upload
    """
    # Group secrets by source_path
    by_path: Dict[str, List[AnalyzedSecret]] = defaultdict(list)
    for secret in result.analyzed_secrets:
        by_path[secret.gathered_secret.metadata.source_path].append(secret)

    items = []
    for path, secrets in by_path.items():
        items.append(
            SecretCollectionItem(
                source_type="demo",
                source_id={"account_id": source_name},
                resource_key=path,
                secrets=[
                    SecretItem(
                        hash=s.gg_hash,
                        length=s.gg_length,
                        sub_path=s.gathered_secret.metadata.secret_name,
                        detector=s.detector_display_name,
                        validity=s.validity,
                        leaked=s.hmsl_leaked,
                    )
                    for s in secrets
                ],
                fetched_at=result.fetched_at,
            )
        )

    return InventoryPayload(
        source_type="demo",
        source_id={"account_id": source_name},
        source_name=source_name,
        items=items,
        env=env,
        agent_version=f"ggshield/{__version__}",
    )


def build_inventory_from_scan(
    secrets: List[GatheredSecret],
    source_name: str,
    env: Optional[str] = "development",
) -> InventoryPayload:
    """
    Transform GatheredSecrets into inventory payload (no enrichment).

    For --skip-analysis mode - only hashes, no detector/validity/leak info.

    Args:
        secrets: List of gathered secrets from scan
        source_name: Machine hostname or custom source name
        env: Environment classification (default: development)

    Returns:
        InventoryPayload ready for upload
    """
    from ggshield.verticals.hmsl.crypto import hash_string

    # Group secrets by source_path
    by_path: Dict[str, List[GatheredSecret]] = defaultdict(list)
    for secret in secrets:
        by_path[secret.metadata.source_path].append(secret)

    fetched_at = datetime.now(timezone.utc).isoformat()
    items = []
    for path, path_secrets in by_path.items():
        items.append(
            SecretCollectionItem(
                source_type="demo",
                source_id={"account_id": source_name},
                resource_key=path,
                secrets=[
                    SecretItem(
                        hash=hash_string(s.value),
                        length=len(s.value.encode("utf-8")),
                        sub_path=s.metadata.secret_name,
                    )
                    for s in path_secrets
                ],
                fetched_at=fetched_at,
            )
        )

    return InventoryPayload(
        source_type="demo",
        source_id={"account_id": source_name},
        source_name=source_name,
        items=items,
        env=env,
        agent_version=f"ggshield/{__version__}",
    )
