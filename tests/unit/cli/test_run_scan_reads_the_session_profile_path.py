#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan runner reads the session's profile path through a name it imports.

Why this file exists
--------------------
``_run_scan`` imports what it needs from ``cli.mcp.profile_registry`` inside the
function, and one of the names it calls,
``resolve_session_config_path``, was missing from that import. Python resolves a
name a function never assigns at call time, so nothing flagged it until a scan
reached the line: the runner raised ``NameError`` before it marked the entry
RUNNING, and every scan started through the MCP route died there.

This drives the real runner to that line. The profile registry's reader is
replaced by a double so the test reads which name the runner called and with
what, and the scan itself by a stub, so nothing runs. Without the import the
runner raises before the double is reached.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli.mcp_tools import _run_scan_async
from automated_security_helper.core.resource_management.scan_registry import (
    ScanRegistry,
    ScanRegistryEntry,
)

pytestmark = pytest.mark.unit

_TOOLS = "automated_security_helper.cli.mcp_tools"
_PROFILE_REGISTRY = "automated_security_helper.cli.mcp.profile_registry"
_RUN_ASH_SCAN = "automated_security_helper.interactions.run_ash_scan.run_ash_scan"


def test_the_runner_reads_the_session_profile_path_and_goes_on_to_the_scan(tmp_path):
    registry = MagicMock(spec=ScanRegistry)
    registry.get_scan.return_value = ScanRegistryEntry(
        scan_id="scan-1",
        directory_path=str(tmp_path / "src"),
        output_directory=str(tmp_path / "out"),
    )

    with (
        patch(f"{_TOOLS}.get_scan_registry", return_value=registry),
        patch(
            f"{_PROFILE_REGISTRY}.resolve_session_config_path", return_value=None
        ) as resolve_profile_path,
        patch(_RUN_ASH_SCAN) as run_ash_scan,
    ):
        asyncio.run(
            _run_scan_async(
                scan_id="scan-1",
                directory_path=str(tmp_path / "src"),
                output_dir=str(tmp_path / "out"),
                severity_threshold="MEDIUM",
            )
        )

    # The runner asked for the profile of the session the scan belongs to (none
    # here), and having no profile to snapshot it ran the scan.
    resolve_profile_path.assert_any_call(None)
    run_ash_scan.assert_called_once()
