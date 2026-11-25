# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
from typing import Annotated, Optional

import typer
import yaml

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.core.enums import AshExitCode
from automated_security_helper.utils.console import echo
from automated_security_helper.utils.content_databases import (
    content_db_staleness_flag_overrides,
)
from automated_security_helper.utils.offline_cache_check import (
    OfflineCacheTool,
    check_offline_cache,
)
from automated_security_helper.utils.terminal_text import shown_on_one_line


def check_dependencies(
    offline: Annotated[
        bool, typer.Option("--offline", help="Check local offline cache files.")
    ] = False,
    tool: Annotated[
        Optional[list[OfflineCacheTool]],
        typer.Option(
            "--tool", help="Check this tool only. Repeat to select both tools."
        ),
    ] = None,
    config: Annotated[
        Optional[str],
        typer.Option(
            "--config", "-c", help="Use the staleness policy from this ASH config file."
        ),
    ] = None,
    source_dir: Annotated[
        Path,
        typer.Option(
            "--source-dir",
            exists=True,
            file_okay=False,
            help="Directory the offline scan would scan.",
        ),
    ] = Path("."),
    allow_stale_content_db: Annotated[
        Optional[bool],
        typer.Option(
            "--allow-stale-content-db/--no-allow-stale-content-db",
            help="Override the configured age policy for all checked databases.",
        ),
    ] = None,
) -> None:
    """Check Grype and Trivy cache metadata without running or downloading tools."""
    if not offline:
        echo("Error: dependencies check requires --offline.", err=True)
        raise typer.Exit(ASH_EXIT_USAGE_ERROR)

    overrides = (
        content_db_staleness_flag_overrides(allow_stale=allow_stale_content_db)
        if allow_stale_content_db is not None
        else []
    )
    try:
        settings = resolve_config(
            config_path=config,
            source_dir=source_dir,
            config_overrides=overrides,
            fallback_to_default=config is None,
        )
    except (ValueError, OSError, yaml.YAMLError):
        echo(
            "Error: could not load the ASH configuration. Run ash config validate for details.",
            err=True,
        )
        raise typer.Exit(AshExitCode.INVALID_CONFIG) from None

    blocked = False
    for name in dict.fromkeys(tool or list(OfflineCacheTool)):
        result = check_offline_cache(name, settings)
        policy_source = f" ({result.policy_source})" if result.policy_source else ""
        echo(
            shown_on_one_line(
                f"{result.tool.value}: {result.state.value}; policy: {result.policy.value}{policy_source}; "
                f"{'blocked' if result.blocks else 'allowed'}"
            )
        )
        echo(shown_on_one_line(f"  database: {result.database.as_posix()}"))
        if result.built is not None:
            echo(f"  timestamp: {result.built.isoformat()}; max age: {result.max_age}")
        if result.detail:
            echo(shown_on_one_line(f"  {result.detail}"))
        blocked |= result.blocks
    if blocked:
        raise typer.Exit(AshExitCode.SCAN_ERRORS)
