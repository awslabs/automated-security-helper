# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_config decides whether the client named the file from one reading.

``client_named_config_is_untrusted`` reads the filesystem (a resolve and a
samefile). get_config uses its answer twice for a named config: to choose the
tree the answer is judged for, when a network session delivered nothing, and to
choose whether the file is resolved against the session's trusted base. Each use
used to ask on its own, with the configuration pre-check's reads between them, so
a file that changed in between could be judged for no tree and then resolved as
the operator's, or the other way round. The second use now takes the first
reading, and a call that needs only one asks once.

The reads are counted through a recorder around the real predicate, and the load
is replaced by a recorder that stops the answer once it has been handed its
judgment, as in the tests of the tree a remote session's file is judged for.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.cli.mcp import sandbox, source_delivery
from automated_security_helper.cli.mcp.profile_registry import (
    DEFAULT_SESSION_ID,
    clear_all_session_state,
    clear_profile_registry,
)
from automated_security_helper.config import resolve_config as resolve_config_module

pytestmark = pytest.mark.unit

REMOTE_SESSION = "client-1"


class _Stop(Exception):
    """Ends the answer once the load has been handed its judgment."""


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Dict[str, Path]:
    """An operator config root holding one file, a scan root holding another, and
    no delivered source."""
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    (operator / "ash.yaml").write_text("project_name: operator\n", encoding="utf-8")
    (scan_root / "ash.yaml").write_text("project_name: client\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan_root))
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(operator))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    for session_id in (REMOTE_SESSION, DEFAULT_SESSION_ID):
        source_delivery._drop_session_source_dir(session_id)
    yield {
        "operator_file": operator / "ash.yaml",
        "client_file": scan_root / "ash.yaml",
    }
    for session_id in (REMOTE_SESSION, DEFAULT_SESSION_ID):
        source_delivery._drop_session_source_dir(session_id)
    clear_profile_registry()
    clear_all_session_state()


@pytest.fixture
def reads(monkeypatch: pytest.MonkeyPatch) -> List[str]:
    """The paths ``client_named_config_is_untrusted`` was asked about, with the
    load replaced so the answer stops once the judgment is made."""
    asked: List[str] = []
    real = sandbox.client_named_config_is_untrusted

    def counting(path: Any, **kwargs: Any) -> bool:
        asked.append(str(path))
        return real(path, **kwargs)

    def stop_at_the_load(**kwargs: Any) -> None:
        raise _Stop

    monkeypatch.setattr(sandbox, "client_named_config_is_untrusted", counting)
    monkeypatch.setattr(resolve_config_module, "resolve_config", stop_at_the_load)
    return asked


def test_a_remote_sessions_client_named_file_is_read_once(_server, reads) -> None:
    """The file is the client's and the session delivered nothing, so both uses
    of the reading are reached; the second takes the first's answer."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    with pytest.raises(_Stop):
        mcp_get_config(
            config_path=str(_server["client_file"]), session_id=REMOTE_SESSION
        )

    assert reads == [str(_server["client_file"])], reads


def test_a_remote_sessions_granted_file_is_read_once(_server, reads) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    with pytest.raises(_Stop):
        mcp_get_config(
            config_path=str(_server["operator_file"]), session_id=REMOTE_SESSION
        )

    assert reads == [str(_server["operator_file"])], reads


def test_a_file_named_under_a_delivered_source_is_read_once(
    _server, reads, monkeypatch, tmp_path
) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    delivered = tmp_path / "delivered"
    delivered.mkdir()
    monkeypatch.setattr(
        source_delivery, "get_session_source_dir", lambda session_id: delivered
    )

    with pytest.raises(_Stop):
        mcp_get_config(
            config_path=str(_server["client_file"]), session_id=REMOTE_SESSION
        )

    assert reads == [str(_server["client_file"])], reads


def test_the_local_client_reads_the_named_file_once(_server, reads) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    with pytest.raises(_Stop):
        mcp_get_config(config_path=str(_server["operator_file"]), session_id=None)

    assert reads == [str(_server["operator_file"])], reads
