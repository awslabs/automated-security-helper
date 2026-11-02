# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan refused before its thread ran records its reason redacted.

The runner's own try begins at the RUNNING mark; a refusal in the set-up
before it (the path predicate, the bound profile's resolution, the session's
client rules) closes the entry FAILED itself. Every other reason the runner
records or logs is written through error_text with the scan's environment
values, so a text that quotes a value the configuration read is redacted; this
arm wrote the raw str(exc) into the entry's error_message, which
get_scan_progress hands to the client, and into the log.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.utils.log import ASHLogger

pytestmark = pytest.mark.unit

SESSION = "refused-before-running"
SECRET = "a-value-the-session-config-read"


def _a_scan(tmp_path: Path, registry: ScanRegistry) -> tuple[Path, Path, str]:
    source = tmp_path / "project"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    named = tmp_path / "named.yaml"
    named.write_text("project_name: named\n", encoding="utf-8")
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    scan_id = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )
    return source, named, scan_id


def test_a_refusal_before_the_runner_shows_no_value_the_config_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red at the base: the raw refusal text, value included, reached the entry
    and the log."""
    from automated_security_helper.cli.mcp import sandbox

    registry = ScanRegistry()
    logger = MagicMock(spec=ASHLogger)
    source, named, scan_id = _a_scan(tmp_path, registry)

    def a_judgment_that_quotes_the_value(path, *, session_id=None):
        raise RuntimeError(f"cannot judge the path: {SECRET}")

    monkeypatch.setattr(
        sandbox, "client_named_config_is_untrusted", a_judgment_that_quotes_the_value
    )
    with (
        patch.object(mcp_tools, "get_scan_registry", return_value=registry),
        patch.object(mcp_tools, "_logger", logger),
    ):
        asyncio.run(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(source),
                output_dir=str(source / ".ash" / "ash_output"),
                severity_threshold=None,
                config_path=str(named),
                session_id=SESSION,
                environment_values=(SECRET,),
            )
        )

    entry = registry.get_scan(scan_id)
    assert entry is not None
    assert entry.status is MCScanStatus.FAILED, entry.status
    message = entry.error_message or ""
    # Control: the refusal's own words reached the entry, so the assertions
    # below measure redaction, not absence.
    assert "cannot judge the path" in message, message
    assert SECRET not in message, message
    logged = str(logger.mock_calls)
    assert "refused" in logged, logged
    assert SECRET not in logged, logged
