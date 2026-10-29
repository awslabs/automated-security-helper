# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace policy file that is a symlink is judged by every path it was reached by.

The policy beside a delivered definition may be a link to a file elsewhere. It
is the client's wherever the link points, so its entries are marked and the MCP
tools refuse it, and an MCP session's gate covers the file it reaches before
anything reads it. An error about a client's policy file says where each
problem is, not what the file holds.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, List
from unittest.mock import patch

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_all_session_state,
)
from tests.utils.delivered_trees import clone, write

pytestmark = pytest.mark.unit

SESSION = "client-1"

#: Text of a policy file that must not reach the client.
CANARY = "canary-pol-3f9a1c"

POLICY = (
    "workspace:\n"
    "  suppressions:\n"
    "    - path: 'app/tests/**'\n"
    "      reason: tests\n"
    "  ignore_paths:\n"
    "    - path: '**/vendor'\n"
    "      reason: third party\n"
)


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    workspace = tmp_path / "workspaces"
    host = tmp_path / "host"
    host.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    yield {"workspace": workspace, "host": host, "tmp": tmp_path}
    clear_profile_registry()
    clear_all_session_state()


def _delivered(server, layout: str, text: str) -> Path:
    """A delivered workspace whose policy is in the tree or a link to a host file."""
    files = {
        "dev.code-workspace": json.dumps({"folders": [{"path": "app"}]}),
        "app/main.py": "x = 1\n",
    }
    links = {}
    if layout == "in place":
        files[".ash/ash-workspace.yaml"] = text
    else:
        links[".ash/ash-workspace.yaml"] = write(
            server["host"] / "ash-workspace.yaml", text
        )
    return clone(server["tmp"], files, links, SESSION)


def _policy_reads(during) -> List[Path]:
    """The policy files read while ``during`` runs, resolved."""
    from automated_security_helper.workspace import policy

    read: List[Path] = []
    real = policy._read_policy_document

    def recording(path: Path, *args: Any, **kwargs: Any) -> Any:
        read.append(Path(path).resolve())
        return real(path, *args, **kwargs)

    with patch.object(policy, "_read_policy_document", recording):
        during()
    return read


# ---------------------------------------------------------------------------
# A delivered policy is the client's wherever its link points
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("layout", ["in place", "linked"])
def test_a_delivered_policys_entries_are_marked(
    _server, monkeypatch: pytest.MonkeyPatch, layout: str
) -> None:
    from automated_security_helper.workspace.resolver import resolve_workspace

    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(_server["host"]))
    source = _delivered(_server, layout, POLICY)

    plan = resolve_workspace(source / "dev.code-workspace")

    (project,) = plan.projects
    entries = list(project.policy_suppressions) + list(project.policy_ignore_paths)
    assert [entry.client_supplied for entry in entries] == [True, True]
    assert (
        plan.workspace_config_source
        == Path(os.path.abspath(source / ".ash" / "ash-workspace.yaml")).as_posix()
    )


def test_the_mcp_tools_refuse_a_delivered_link_to_a_set_aside_policy(
    _server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The file is the operator's, but the client chose it by delivering the link."""
    from automated_security_helper.cli.mcp import workspace as ws

    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(_server["host"]))
    source = _delivered(_server, "linked", POLICY)

    result = asyncio.run(
        ws.mcp_resolve_workspace(str(source / "dev.code-workspace"), session_id=SESSION)
    )

    assert result.get("success") is False, result
    assert result.get("exit_code") == 4, result
    assert "delivered by an MCP client" in result["error"], result
    assert str(_server["host"]) not in repr(result)


# ---------------------------------------------------------------------------
# A policy that links out of the roots is refused before it is read
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool", ["mcp_resolve_workspace", "mcp_scan_workspace"])
def test_a_policy_linking_out_of_the_roots_is_refused_unread(
    _server, tool: str
) -> None:
    from automated_security_helper.cli.mcp import workspace as ws

    source = _delivered(_server, "linked", f"workspace: {{}}\n# {CANARY}\n")
    out: List[Any] = []

    read = _policy_reads(
        lambda: out.append(
            asyncio.run(
                getattr(ws, tool)(
                    str(source / "dev.code-workspace"), session_id=SESSION
                )
            )
        )
    )

    (result,) = out
    assert result.get("success") is False, result
    assert result.get("error_type") == "config_input_not_permitted", result
    assert result.get("exit_code") == 4, result
    assert (_server["host"] / "ash-workspace.yaml").resolve() not in read
    assert "ash-workspace.yaml" in result["error"], result
    assert CANARY not in repr(result)
    assert str(_server["host"]) not in repr(result)


# ---------------------------------------------------------------------------
# An error about a client's policy file does not quote it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text, where",
    [
        (f"workspace:\n  max_severity_threshold: {CANARY}\n", "max_severity_threshold"),
        (
            (
                "workspace:\n  suppressions:\n    - path: 'app/**'\n      reason: r\n"
                f"      expiration: '{CANARY}'\n"
            ),
            "expiration: invalid value (value_error)",
        ),
        (f"workspace:\n  {CANARY}: 1\n", "workspace.<key>: Extra inputs"),
        (f"workspace:\n  suppressions: [{{path: '{CANARY}'\n", "line"),
        (f"- {CANARY}\n", "mapping"),
    ],
    ids=[
        "invalid value",
        "validator message",
        "unknown key",
        "unparseable",
        "not a mapping",
    ],
)
def test_an_error_about_a_delivered_policy_names_where_not_what(
    _server, text: str, where: str
) -> None:
    from automated_security_helper.core.exceptions import WorkspaceDefinitionError
    from automated_security_helper.workspace.resolver import resolve_workspace

    source = _delivered(_server, "in place", text)

    with pytest.raises(WorkspaceDefinitionError) as raised:
        resolve_workspace(source / "dev.code-workspace")

    message = str(raised.value)
    assert "ash-workspace.yaml" in message
    assert where in message
    assert CANARY not in message


def test_an_operators_policy_error_still_quotes_it(tmp_path: Path) -> None:
    """On the CLI the file is the operator's own, and the value helps fix it."""
    from automated_security_helper.core.exceptions import WorkspaceDefinitionError
    from automated_security_helper.workspace.resolver import resolve_workspace

    root = tmp_path / "wsroot"
    write(root / "dev.code-workspace", json.dumps({"folders": [{"path": "app"}]}))
    write(root / "app" / "main.py", "x = 1\n")
    write(
        root / ".ash" / "ash-workspace.yaml",
        f"workspace:\n  max_severity_threshold: {CANARY}\n",
    )

    with pytest.raises(WorkspaceDefinitionError) as raised:
        resolve_workspace(root / "dev.code-workspace")

    assert CANARY in str(raised.value)
