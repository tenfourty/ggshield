"""
Machine command group for local machine secret scanning.
"""

from typing import Any

import click

from ggshield.cmd.machine.analyze import analyze_cmd
from ggshield.cmd.machine.check import check_cmd
from ggshield.cmd.machine.ping import ping_cmd
from ggshield.cmd.machine.scan import scan_cmd
from ggshield.cmd.machine.scan_and_send import scan_and_send_cmd
from ggshield.cmd.utils.common_options import add_common_options
from ggshield.utils.click import NaturalOrderGroup


@click.group(
    cls=NaturalOrderGroup,
    commands={
        "scan": scan_cmd,
        "check": check_cmd,
        "analyze": analyze_cmd,
        "scan-and-send": scan_and_send_cmd,
        "ping": ping_cmd,
    },
)
@add_common_options()
def machine_group(**kwargs: Any) -> None:
    """
    Commands for machine-wide secret scanning and management.

    Scan your local machine for secrets in environment variables,
    configuration files, and private key files. Check if secrets
    have been publicly exposed or analyze them with the GitGuardian API.

    \b
    Commands:
      scan          - Fast local scan (no network calls)
      check         - Scan + check for public leaks (sends hashes only)
      analyze       - Full analysis with GitGuardian API (sends secrets)
      scan-and-send - Analyze + upload to GitGuardian inventory
      ping          - Test connectivity to GitGuardian platform
    """
