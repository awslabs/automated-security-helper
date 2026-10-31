# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_config judges a named config for no tree when a remote session delivered nothing.

With a named ``config_path`` and no ``search_dir``, the answer is judged for the
target a scan of the session would take: the session's delivered source. A
network session that delivered nothing has no such target, and ``run_ash_scan``
refuses to fall back to the server's working directory for it, so a file the
CLIENT named (outside every granted config root) is judged for no scanned tree,
the fail-closed path a deleted working directory already takes. A file the
OPERATOR granted (inside ``ASH_MCP_ALLOWED_CONFIG_ROOTS``) keeps the
working-directory judgment: under the no-tree load such a file, when it sits in
a checkout, joined the confinement and its unimportable plugin modules were
dropped, so the answer showed a configuration every scan of it refuses. The
local client (the stdio session) keeps its working directory as its own tree,
and a delivered source keeps standing in for the session that delivered it.

The judgment is read where the load receives it: ``resolve_config`` is replaced
by a recorder that keeps the ``scanned_root`` and ``no_scanned_tree`` arguments
and stops the answer there, so nothing of the configuration is resolved.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    clear_all_session_state,
    clear_profile_registry,
)
from automated_security_helper.config import resolve_config as resolve_config_module
from automated_security_helper.cli.mcp import source_delivery
from automated_security_helper.config.sandbox_grants import working_directory

pytestmark = pytest.mark.unit

REMOTE_SESSION = "client-1"


class _Stop(Exception):
    """Ends the answer once the load has been handed its judgment."""


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Dict[str, Path]:
    """An operator config root holding the named file, and no delivered source."""
    workspace = tmp_path / "workspaces"
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    (operator / "ash.yaml").write_text("project_name: named\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan_root))
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(operator))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    # "Delivered nothing" is this module's premise, and the delivered-source
    # record is process-wide: an earlier test that uploaded a tree for the same
    # session id (another module's upload under its own tmp_path) left the
    # record behind, and the judgment then read that tree as this session's.
    source_delivery._drop_session_source_dir(REMOTE_SESSION)
    yield {"operator": operator, "named": operator / "ash.yaml"}
    source_delivery._drop_session_source_dir(REMOTE_SESSION)
    clear_profile_registry()
    clear_all_session_state()


def _judgment(monkeypatch: pytest.MonkeyPatch) -> Dict[str, Any]:
    """Replace the load with a recorder of the judgment get_config hands it."""
    seen: Dict[str, Any] = {}

    def record(**kwargs: Any) -> None:
        seen["scanned_root"] = kwargs.get("scanned_root")
        seen["no_scanned_tree"] = kwargs.get("no_scanned_tree")
        raise _Stop

    monkeypatch.setattr(resolve_config_module, "resolve_config", record)
    return seen


def test_a_remote_sessions_client_named_file_is_judged_for_no_tree(
    _server, monkeypatch, tmp_path
) -> None:
    """A file the client named outside every granted config root, under a
    network session that delivered nothing: no tree a scan of it could take, so
    the no-tree judgment."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    # Inside the scan root the server may scan, outside every granted config
    # root: a file the client named, not one the operator set aside.
    named = tmp_path / "scan-root" / "ash.yaml"
    named.write_text("project_name: named\n", encoding="utf-8")
    seen = _judgment(monkeypatch)

    with pytest.raises(_Stop):
        mcp_get_config(config_path=str(named), session_id=REMOTE_SESSION)

    assert seen["scanned_root"] is None
    assert seen["no_scanned_tree"] is True


def test_a_remote_sessions_granted_file_keeps_the_working_directory(
    _server, monkeypatch
) -> None:
    """The operator's file (inside ASH_MCP_ALLOWED_CONFIG_ROOTS) keeps the
    working-directory judgment under a network session that delivered nothing.
    Judged for no tree, a granted file sitting in a checkout joined the no-tree
    confinement and its unimportable ``ash_plugin_modules`` entries were dropped,
    so get_config answered a configuration every scan of it refuses (the pin in
    test_get_config_refuses_plugin_modules_a_scan_refuses.py); under the
    working-directory judgment the file is outside the tree, its entries are
    kept and judged, and the refusal answers."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    seen = _judgment(monkeypatch)

    with pytest.raises(_Stop):
        mcp_get_config(config_path=str(_server["named"]), session_id=REMOTE_SESSION)

    assert seen["scanned_root"] == working_directory()
    assert seen["no_scanned_tree"] is False


def test_a_granted_file_inside_the_working_directory_keeps_that_judgment(
    _server, monkeypatch, tmp_path
) -> None:
    """The judgment follows who granted the file, not where the process runs.
    The test above holds only while the granted root sits outside the working
    directory; run from a directory that contains it, the file is inside the
    tree the judgment names, and the answer must be the same."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    monkeypatch.chdir(tmp_path)
    assert _server["named"].resolve().is_relative_to(working_directory()), (
        "the control: the granted file must sit inside the working directory"
    )
    seen = _judgment(monkeypatch)

    with pytest.raises(_Stop):
        mcp_get_config(config_path=str(_server["named"]), session_id=REMOTE_SESSION)

    assert seen["scanned_root"] == working_directory()
    assert seen["no_scanned_tree"] is False


def test_the_local_client_keeps_its_working_directory(_server, monkeypatch) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    seen = _judgment(monkeypatch)

    with pytest.raises(_Stop):
        mcp_get_config(config_path=str(_server["named"]), session_id=None)

    assert seen["scanned_root"] == working_directory()
    assert seen["no_scanned_tree"] is False


def test_a_delivered_source_stands_in_for_the_session_that_delivered_it(
    _server, monkeypatch, tmp_path
) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    delivered = tmp_path / "delivered"
    delivered.mkdir()
    monkeypatch.setattr(
        source_delivery, "get_session_source_dir", lambda session_id: delivered
    )
    seen = _judgment(monkeypatch)

    with pytest.raises(_Stop):
        mcp_get_config(config_path=str(_server["named"]), session_id=REMOTE_SESSION)

    assert seen["scanned_root"] == delivered
    assert seen["no_scanned_tree"] is False
