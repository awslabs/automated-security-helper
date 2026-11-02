# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace project's config that is a symlink is judged by the link, at plan and scan time.

A workspace is resolved once into a plan and then each project's config is
resolved again when the project is scanned (``workspace/execution.py``). Both
resolutions read the config by the path the project's directory holds it at,
so a ``.ash/.ash.yaml`` that links to a file outside the tree is held to the
limits of a config inside the tree on the CLI, and to a client's limits when an
MCP client delivered the tree, as a single-directory scan holds it.
"""

from __future__ import annotations

import asyncio
import builtins
import io
import json
import os
import sys
from pathlib import Path
from typing import Any, List
from unittest.mock import patch

import pytest
import yaml

from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_all_session_state,
)
from tests.utils.delivered_trees import clone, symlink, write

pytestmark = pytest.mark.unit

SESSION = "client-1"

SUPPRESSIONS = (
    "project_name: linked\n"
    "global_settings:\n"
    "  suppressions:\n"
    "    - rule_id: B101\n"
    "      path: 'tests/**'\n"
    "      reason: asserts in tests\n"
)


class _Stop(Exception):
    pass


#: On Windows a project's discovery under an MCP session's gate refuses a linked
#: config source whose chain leads to a network share before it opens it
#: (``config_sources._permitted``: resolving a link there can open a connection
#: to the host a UNC target names), and judges a link that leads to a local file
#: as the file it names, as on POSIX. The tests that need the link followed have
#: not been measured on a Windows host with links, so they stay skipped there.
#: The refusals this file pins (``_assert_refused_unread``) hold on every platform.
follows_a_link = pytest.mark.skipif(
    sys.platform == "win32",
    reason="not yet measured on a Windows host with links (see config_sources._permitted)",
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


def _grants(tmp_path: Path) -> str:
    granted = tmp_path / "granted"
    granted.mkdir(exist_ok=True)
    return yaml.safe_dump(
        {"project_name": "g", "sandbox": {"extra_read_paths": [str(granted)]}}
    )


def _cli_workspace(tmp_path: Path, layout: str) -> Path:
    """A workspace on disk whose one project's config is in place or an outward link."""
    root = tmp_path / "wsroot"
    workspace = write(
        root / "dev.code-workspace", json.dumps({"folders": [{"path": "app"}]})
    )
    write(root / "app" / "main.py", "x = 1\n")
    target = root / "app" / ".ash" / ".ash.yaml"
    if layout == "in place":
        write(target, _grants(tmp_path))
    else:
        symlink(target, write(tmp_path / "outside" / "grant.yaml", _grants(tmp_path)))
    return workspace


def _delivered_workspace(server, text: str) -> Path:
    """A delivered workspace whose project config links to a host file holding ``text``."""
    host_file = write(server["host"] / "ash.yaml", text)
    return clone(
        server["tmp"],
        {
            "dev.code-workspace": json.dumps({"folders": [{"path": "app"}]}),
            "app/main.py": "x = 1\n",
        },
        {"app/.ash/.ash.yaml": host_file},
        SESSION,
    )


# ---------------------------------------------------------------------------
# The plan and the scan both read the config by its path in the project
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("layout", ["in place", "linked out"])
def test_a_cli_workspace_scan_confines_a_project_configs_grants(
    tmp_path: Path, layout: str
) -> None:
    """As a single-directory scan of the same project does."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.workspace import execution
    from automated_security_helper.workspace.resolver import resolve_workspace

    workspace = _cli_workspace(tmp_path, layout)

    plan = resolve_workspace(workspace)
    (project,) = plan.projects
    settings = execution.ProjectScanSettings(output_dir=tmp_path / "out")
    config = execution._project_config_with_policy(project, settings)

    assert list(config.sandbox.extra_read_paths) == []
    single = resolve_config(source_dir=workspace.parent / "app")
    assert list(single.sandbox.extra_read_paths) == []


def test_the_plan_names_a_linked_project_config_by_its_path_in_the_project(
    tmp_path: Path,
) -> None:
    from automated_security_helper.workspace.resolver import resolve_workspace

    workspace = _cli_workspace(tmp_path, "linked out")

    (project,) = resolve_workspace(workspace).projects

    assert (
        project.config_source
        == (workspace.parent.resolve() / "app" / ".ash" / ".ash.yaml").as_posix()
    )


@follows_a_link
def test_an_mcp_workspace_scan_marks_a_delivered_links_suppressions(
    _server, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The host file is in a directory the operator set aside, so it is read."""
    from automated_security_helper.cli.mcp import workspace as ws
    from automated_security_helper.workspace import execution

    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(_server["host"]))
    source = _delivered_workspace(_server, SUPPRESSIONS)
    real = execution._project_config_with_policy
    resolved: List[Any] = []

    def stop_after(project, settings):
        resolved.append(real(project, settings))
        raise _Stop

    with patch.object(execution, "_project_config_with_policy", stop_after):
        try:
            asyncio.run(
                ws.mcp_scan_workspace(
                    str(source / "dev.code-workspace"), session_id=SESSION
                )
            )
        except _Stop:
            pass

    assert resolved, "the scan never resolved the project's config"
    suppressions = resolved[-1].global_settings.suppressions
    assert [entry.client_supplied for entry in suppressions] == [True]


# ---------------------------------------------------------------------------
# The MCP workspace tools refuse a project config that links out of the roots
# ---------------------------------------------------------------------------

#: A host config whose text must not reach the client.
CANARY = "canary-ws-6d0b2e"
LINK_OUT = f"project_name: {CANARY}\nglobal_settings:\n  severity_threshold: CRITICAL\n"


def _assert_refused_unread(server, result: Any, read: List[Path]) -> None:
    host_file = (server["host"] / "ash.yaml").resolve()
    assert result.get("success") is False, result
    assert result.get("error_type") == "config_input_not_permitted", result
    assert result.get("exit_code") == 4, result
    assert host_file not in read
    assert CANARY not in repr(result)
    assert str(server["host"]) not in repr(result)


def test_a_remote_resolve_workspace_refuses_a_project_config_linking_out(
    _server,
) -> None:
    from automated_security_helper.cli.mcp import workspace as ws
    from tests.utils.delivered_trees import reads

    source = _delivered_workspace(_server, LINK_OUT)
    out: List[Any] = []

    read = reads(
        lambda: out.append(
            asyncio.run(
                ws.mcp_resolve_workspace(
                    str(source / "dev.code-workspace"), session_id=SESSION
                )
            )
        )
    )

    (result,) = out
    _assert_refused_unread(_server, result, read)
    assert ".ash/.ash.yaml" in result["error"], result


def test_a_remote_scan_workspace_refuses_it_too(_server) -> None:
    from automated_security_helper.cli.mcp import workspace as ws
    from tests.utils.delivered_trees import reads

    source = _delivered_workspace(_server, LINK_OUT)
    out: List[Any] = []

    read = reads(
        lambda: out.append(
            asyncio.run(
                ws.mcp_scan_workspace(
                    str(source / "dev.code-workspace"), session_id=SESSION
                )
            )
        )
    )

    (result,) = out
    _assert_refused_unread(_server, result, read)


def test_the_scan_side_refuses_it_without_the_plans_check(_server, tmp_path) -> None:
    """Should the file change after the plan, the scan's own resolve refuses it."""
    from automated_security_helper.cli.mcp.sandbox import config_base_gate
    from automated_security_helper.core.exceptions import (
        ASHConfigInputNotPermittedError,
    )
    from automated_security_helper.workspace import execution
    from automated_security_helper.workspace.resolver import resolve_workspace
    from tests.utils.delivered_trees import reads

    # At plan time the link stays inside the delivered tree.
    source = clone(
        _server["tmp"],
        {
            "dev.code-workspace": json.dumps({"folders": [{"path": "app"}]}),
            "app/main.py": "x = 1\n",
            "app/conf/real.yaml": "project_name: first\n",
        },
        {"app/.ash/.ash.yaml": Path("../conf/real.yaml")},
        SESSION,
    )
    (project,) = resolve_workspace(
        source / "dev.code-workspace", permit_base=config_base_gate(SESSION)
    ).projects
    # The link now points outside every root.
    link = source / "app" / ".ash" / ".ash.yaml"
    link.unlink()
    symlink(link, write(_server["host"] / "ash.yaml", LINK_OUT))
    settings = execution.ProjectScanSettings(
        output_dir=tmp_path / "out", config_base_gate=config_base_gate(SESSION)
    )
    raised: List[BaseException] = []

    def run() -> None:
        try:
            execution._project_config_with_policy(project, settings)
        except ASHConfigInputNotPermittedError as exc:
            raised.append(exc)

    read = reads(run)

    assert raised, "the scan resolved a project config outside the roots"
    assert (_server["host"] / "ash.yaml").resolve() not in read
    assert CANARY not in str(raised[0])


@follows_a_link
def test_a_link_into_a_set_aside_directory_is_followed(
    _server, monkeypatch: pytest.MonkeyPatch
) -> None:
    from automated_security_helper.cli.mcp import workspace as ws

    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(_server["host"]))
    source = _delivered_workspace(_server, "project_name: linked\n")

    result = asyncio.run(
        ws.mcp_resolve_workspace(str(source / "dev.code-workspace"), session_id=SESSION)
    )

    assert result.get("success") is True, result
    (project,) = result["projects"]
    assert project["display_label"] == "linked"
    assert str(_server["host"]) not in project["config_source"]


# ---------------------------------------------------------------------------
# A project's config sources are checked before discovery opens any of them
# ---------------------------------------------------------------------------
# Discovery reads a pyproject.toml to see whether it has a [tool.ash] table. One
# that links outside the roots is refused before that, with the same answer
# whether its target is missing, unreadable or readable.

_MARKER = "TARGET-CONTENT-MARKER"
_TARGETS = ["missing", "unreadable", "readable"]


@pytest.fixture
def linked_pyproject(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("mode 0 does not stop root from reading the target")
    from automated_security_helper.cli.mcp.sandbox import (
        ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV,
        ASH_MCP_ALLOWED_ROOTS_ENV,
        ASH_MCP_TRANSPORT_ENV,
    )

    root = tmp_path / "ws"
    write(root / "api" / "app.py", "x = 1\n")
    workspace = write(
        root / "dev.code-workspace", json.dumps({"folders": [{"path": "api"}]})
    )
    elsewhere = tmp_path / "elsewhere"
    targets = {name: elsewhere / f"{name}.toml" for name in _TARGETS}
    write(targets["unreadable"], f'[tool]\nx = "{_MARKER}"\n').chmod(0)
    write(targets["readable"], f'[tool]\nx = "{_MARKER}"\n')
    monkeypatch.setenv(ASH_MCP_TRANSPORT_ENV, "stdio")
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(root))
    monkeypatch.setenv(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, str(root))
    yield root, workspace, targets
    targets["unreadable"].chmod(0o644)


def _record_opens(monkeypatch: pytest.MonkeyPatch) -> List[Path]:
    """Every path opened through os.open, open() or io.open (which Path uses)."""
    opened: List[Path] = []
    real_os_open, real_open = os.open, builtins.open

    def recording_os_open(path, flags, *args, **kwargs):
        opened.append(Path(os.fspath(path)))
        return real_os_open(path, flags, *args, **kwargs)

    def recording_open(file, *args, **kwargs):
        if isinstance(file, (str, bytes, os.PathLike)):
            opened.append(Path(os.fsdecode(file)))
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(os, "open", recording_os_open)
    monkeypatch.setattr(builtins, "open", recording_open)
    monkeypatch.setattr(io, "open", recording_open)
    return opened


@pytest.mark.parametrize("tool", ["mcp_resolve_workspace", "mcp_scan_workspace"])
def test_a_linked_pyproject_is_refused_alike_whatever_it_reaches(
    linked_pyproject, monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    from automated_security_helper.cli.mcp import workspace as ws

    root, workspace, targets = linked_pyproject
    link = root / "api" / "pyproject.toml"
    opened = _record_opens(monkeypatch)
    responses = []
    for target in _TARGETS:
        if os.path.lexists(link):
            link.unlink()
        link.symlink_to(targets[target])
        opened.clear()
        result = asyncio.run(getattr(ws, tool)(str(workspace), session_id="client-one"))
        responses.append(
            (
                target,
                link in opened or targets[target] in opened,
                result.get("success"),
                result.get("exit_code"),
                result.get("error_type"),
                result.get("error"),
            )
        )

    assert not any(was_opened for _, was_opened, *_ in responses), responses
    assert len({tuple(r[2:]) for r in responses}) == 1, responses
    assert responses[0][2:5] == (False, 4, "config_input_not_permitted"), responses
    assert _MARKER not in json.dumps(responses, default=str)
    assert "Errno" not in json.dumps(responses, default=str)


_ASH_DIR_TARGETS = ["missing", "unreadable", "empty", "holding a config"]


def test_a_linked_ash_directory_is_refused_alike_whatever_it_holds(
    linked_pyproject, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Checked as a directory, so an unlistable or empty target answers the same."""
    from automated_security_helper.cli.mcp import workspace as ws

    root, workspace, _ = linked_pyproject
    elsewhere = root.parent / "elsewhere-dirs"
    dirs = {name: elsewhere / name.replace(" ", "-") for name in _ASH_DIR_TARGETS}
    write(dirs["unreadable"] / ".ash.yaml", f"project_name: {_MARKER}\n")
    dirs["unreadable"].chmod(0)
    dirs["empty"].mkdir(parents=True)
    write(dirs["holding a config"] / ".ash.yaml", f"project_name: {_MARKER}\n")
    link = root / "api" / ".ash"
    responses = []
    try:
        for name in _ASH_DIR_TARGETS:
            if os.path.lexists(link):
                link.unlink()
            link.symlink_to(dirs[name], target_is_directory=True)
            result = asyncio.run(
                ws.mcp_resolve_workspace(str(workspace), session_id="client-one")
            )
            responses.append(
                (
                    name,
                    result.get("success"),
                    result.get("exit_code"),
                    result.get("error_type"),
                    result.get("error"),
                )
            )
    finally:
        dirs["unreadable"].chmod(0o755)

    assert len({tuple(r[1:]) for r in responses}) == 1, responses
    assert responses[0][1:4] == (False, 4, "config_input_not_permitted"), responses
    assert _MARKER not in json.dumps(responses, default=str)


def test_control_the_opens_are_recorded(linked_pyproject, monkeypatch) -> None:
    """The recorder sees discovery read a pyproject.toml, so the test above can fail."""
    from automated_security_helper.config.config_sources import (
        discover_config_source,
    )

    root, _, targets = linked_pyproject
    link = root / "api" / "pyproject.toml"
    link.symlink_to(targets["readable"])
    opened = _record_opens(monkeypatch)

    discover_config_source(root / "api")

    assert link in opened or targets["readable"] in opened, opened
