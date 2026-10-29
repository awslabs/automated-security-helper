# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan's pre-checks discover the config under the session's gate.

Before a scan of a directory with no named config, ``scan_directory`` runs
checks that each discover the config the scan would read, among them the
refusal of a config source outside the session's grant and the client-rules
denial. A discovered name can be a link to any file on the server, so
discovery is handed the session's ``config_base_gate``, which checks every
source by the path it resolves to before opening any
(``config_sources.discover_config_source``). Without it the client-rules check
read the file the link reaches, even one the gate refuses: when it is called on
its own, or when the link changes after the first check passed.

Each check is called here on its own, on a directory whose ``.ash.yaml`` links
to a file outside every root the session may read config from, and the test
records every config file resolution reads.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Dict, List

import pytest

from automated_security_helper.cli import mcp_tools
from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_all_session_state,
)
from automated_security_helper.config import config_sources

pytestmark = pytest.mark.unit

SESSION = "client-1"


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A scan root the session may read, and a directory outside it."""
    scan_root = tmp_path / "scan-root"
    target = scan_root / "target"
    target.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "ash.yaml").write_text("project_name: outside\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan_root))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    yield {"target": target, "outside": outside}
    clear_profile_registry()
    clear_all_session_state()


@pytest.fixture
def resolved(monkeypatch: pytest.MonkeyPatch) -> List[Path]:
    """Every config file the checks hand to resolution, which reads it."""
    seen: List[Path] = []
    real = config_sources.resolve_config_document

    def _record(path, *args, **kwargs):
        seen.append(Path(path))
        return real(path, *args, **kwargs)

    monkeypatch.setattr(config_sources, "resolve_config_document", _record)
    return seen


CHECKS: Dict[str, Callable[[Path], object]] = {
    "client-rules-check": lambda target: mcp_tools._client_config_denial(
        None, target, SESSION, "scan_directory"
    ),
}


@pytest.mark.parametrize("check", sorted(CHECKS))
def test_a_check_reads_no_config_the_session_gate_refuses(_server, resolved, check):
    (_server["target"] / ".ash.yaml").symlink_to(_server["outside"] / "ash.yaml")

    assert CHECKS[check](_server["target"]) is None
    assert resolved == [], resolved


@pytest.mark.parametrize("check", sorted(CHECKS))
def test_control_a_check_reads_the_config_in_the_scanned_directory(
    _server, resolved, check
):
    """The gate admits the directory's own file, and the recorder sees it read."""
    own = _server["target"] / ".ash.yaml"
    own.write_text("project_name: own\n", encoding="utf-8")

    assert CHECKS[check](_server["target"]) is None
    assert resolved == [own], resolved


def test_control_the_session_gate_refuses_the_linked_file(_server):
    """What the checks rely on: the link resolves to a file the gate refuses."""
    from automated_security_helper.cli.mcp.sandbox import config_base_gate

    link = _server["target"] / ".ash.yaml"
    link.symlink_to(_server["outside"] / "ash.yaml")
    permit = config_base_gate(SESSION)

    assert permit(link.resolve()) is False
    assert permit((_server["target"] / "own.yaml").resolve()) is True
