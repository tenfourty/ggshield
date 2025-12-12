"""
Machine ping command - test connectivity to GitGuardian platform.

This command verifies that ggshield can connect to the GitGuardian API
and that the API key is valid.
"""

from __future__ import annotations

import socket
from typing import Any

import click

from ggshield import __version__
from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.errors import ExitCode
from ggshield.verticals.machine.inventory import InventoryClient, NHIAuthError


@click.command()
@click.pass_context
@add_common_options()
@click.option(
    "--source-name",
    type=str,
    default=None,
    help="Override machine hostname as source name.",
)
@click.option(
    "--env",
    type=click.Choice(
        ["production", "staging", "development", "testing", "pre-production"]
    ),
    default="development",
    help="Environment classification.",
)
def ping_cmd(
    ctx: click.Context,
    source_name: str | None,
    env: str,
    **kwargs: Any,
) -> int:
    """
    Test connectivity to GitGuardian NHI platform.

    Sends source information to GitGuardian and verifies that the API key
    is valid for inventory operations.

    \\b
    AUTHENTICATION:
      Requires a service account with 'nhi:send-inventory' scope.
      Set via: GITGUARDIAN_NHI_API_KEY environment variable
      Or use GITGUARDIAN_API_KEY if it has NHI permissions.

    \\b
    Examples:
      export GITGUARDIAN_NHI_API_KEY="your-service-account-key"
      ggshield machine ping                      # Test connectivity
      ggshield machine ping --source-name myhost # Test with custom source name
      ggshield machine ping --env production     # Test with environment
    """
    ctx_obj = ContextObj.get(ctx)
    hostname = source_name or socket.gethostname()

    ui.display_info(f"Testing connectivity to {ctx_obj.config.api_url}...")
    ui.display_info(f"Source name: {hostname}")
    ui.display_info(f"Environment: {env}")

    client = InventoryClient(
        api_url=ctx_obj.config.api_url,
        api_key=ctx_obj.config.nhi_api_key,
        agent_version=f"ggshield/{__version__}",
    )

    try:
        client.ping(hostname, env=env)
        ui.display_info("\n✓ Connection successful")
        ui.display_info("  API key is valid for NHI inventory operations")
        return ExitCode.SUCCESS
    except NHIAuthError as e:
        ui.display_error(f"\n✗ {e}")
        return ExitCode.UNEXPECTED_ERROR
    except Exception as e:
        ui.display_error(f"\n✗ Connection failed: {e}")
        return ExitCode.UNEXPECTED_ERROR
