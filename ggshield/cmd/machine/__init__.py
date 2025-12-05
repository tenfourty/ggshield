"""
Machine command group for local machine secret scanning.
"""

from typing import Any

import click

from ggshield.cmd.machine.scan import scan_cmd
from ggshield.cmd.utils.common_options import add_common_options
from ggshield.utils.click import NaturalOrderGroup


@click.group(
    cls=NaturalOrderGroup,
    commands={
        "scan": scan_cmd,
        # Future: "vault": vault_group,
    },
)
@add_common_options()
def machine_group(**kwargs: Any) -> None:
    """
    Commands for machine-wide secret scanning and management.

    Scan your local machine for secrets in environment variables,
    configuration files, and private key files. Optionally check
    if found secrets have been publicly exposed.
    """
