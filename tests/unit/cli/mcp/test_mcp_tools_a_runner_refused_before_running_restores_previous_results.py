# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan refused in the runner's set-up puts the previous results back.

``mcp_scan_directory`` with ``clean_output`` sets the previous results aside as
soon as the registry gives the scan its directory; the runner puts them back on
every ending that has no results of its own. The runner's set-up arms that
refuse the scan before its thread runs (a bound profile that cannot be written
again, session rules that cannot be read) closed the entry FAILED and returned
without that restore, so the directory stayed empty of the previous results and
the entry did not record whether it held them. They now settle the previous
results as every other ending without results does, and the refusal of a
set-up step that raised unguarded (the client's path predicate, the session
lookup) is recorded the same way instead of leaving the entry PENDING.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.unit

SESSION = "client-one"
RESULTS = "ash_aggregated_results.json"


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from automated_security_helper.cli.mcp import sessions
    from automated_security_helper.cli.mcp.profile_registry import (
        clear_all_session_state,
        clear_profile_registry,
    )

    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "ws"))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    sessions.reset_default_registry_for_tests()
    yield
    sessions.reset_default_registry_for_tests()
    clear_profile_registry()
    clear_all_session_state()


def _scan_with_previous_results_set_aside(tmp_path: Path):
    from automated_security_helper.core.previous_results import PreviousResults
    from automated_security_helper.core.resource_management.scan_registry import (
        ScanRegistry,
    )

    source = tmp_path / "project"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    (output / RESULTS).write_text("{}", encoding="utf-8")
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(source), output_directory=str(output)
    )
    # What mcp_scan_directory's clean_output does once the directory is the scan's.
    PreviousResults(output).set_aside()
    assert not (output / RESULTS).exists()
    return registry, scan_id, source, output


def _run(registry, scan_id: str, source: Path, output: Path, **kwargs: Any) -> None:
    from automated_security_helper.cli import mcp_tools

    with patch.object(mcp_tools, "get_scan_registry", return_value=registry):
        asyncio.run(
            mcp_tools._run_scan(
                scan_id=scan_id,
                directory_path=str(source),
                output_dir=str(output),
                severity_threshold=None,
                session_id=SESSION,
                **kwargs,
            )
        )


def test_session_rules_that_cannot_be_read_put_the_previous_results_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.core.previous_results import holds_restored_results
    from automated_security_helper.core.resource_management.scan_registry import (
        MCScanStatus,
    )

    registry, scan_id, source, output = _scan_with_previous_results_set_aside(tmp_path)

    def unreadable(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the registered profile could not be read")

    monkeypatch.setattr(mcp_tools, "_session_client_rules", unreadable)

    _run(registry, scan_id, source, output)

    entry = registry.get_scan(scan_id)
    assert entry is not None
    assert entry.status is MCScanStatus.FAILED, entry.status
    assert "could not be read" in (entry.error_message or ""), entry.error_message
    assert (output / RESULTS).exists(), sorted(p.name for p in output.iterdir())
    assert holds_restored_results(output)
    assert entry.output_holds_previous_results is True
    assert entry.runner_done.is_set()


def test_a_client_path_predicate_that_raises_is_a_refusal_not_a_pending_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from automated_security_helper.cli.mcp import sandbox
    from automated_security_helper.core.resource_management.scan_registry import (
        MCScanStatus,
    )

    registry, scan_id, source, output = _scan_with_previous_results_set_aside(tmp_path)
    config = source / "ash.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")

    def a_link_loop(*args: Any, **kwargs: Any) -> bool:
        raise RuntimeError("Symlink loop from the config path")

    monkeypatch.setattr(sandbox, "client_named_config_is_untrusted", a_link_loop)

    _run(registry, scan_id, source, output, config_path=str(config))

    entry = registry.get_scan(scan_id)
    assert entry is not None
    assert entry.status is MCScanStatus.FAILED, entry.status
    assert "Symlink loop" in (entry.error_message or ""), entry.error_message
    assert (output / RESULTS).exists()
