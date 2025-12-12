"""
Inventory module for uploading secrets to GitGuardian inventory.
"""

from ggshield.verticals.machine.inventory.builder import (
    build_inventory_from_analysis,
    build_inventory_from_scan,
)
from ggshield.verticals.machine.inventory.client import InventoryClient, NHIAuthError
from ggshield.verticals.machine.inventory.models import (
    InventoryPayload,
    SecretCollectionItem,
    SecretItem,
)


__all__ = [
    "InventoryClient",
    "InventoryPayload",
    "NHIAuthError",
    "SecretCollectionItem",
    "SecretItem",
    "build_inventory_from_analysis",
    "build_inventory_from_scan",
]
