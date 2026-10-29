# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``.ash`` that is a Windows junction out of the roots is refused like a link.

Why this exists
---------------
Config discovery and workspace policy discovery refuse a ``.ash`` linked out of
the directories the session may read config from, before they look at any name
in it (test_a_linked_ash_dir_is_no_oracle.py). ``Path.is_symlink()`` is False
for a Windows junction, so both discoveries also treat a ``.ash`` junction that
leads out of the roots as a link: it is refused before anything in it is looked
at, and the answer is the same whether or not the outside directory holds the
name.

A junction cannot be made here, so each cell builds the one thing that is the
same on every platform, a ``.ash`` that leads to an outside directory, and then
reports it as Windows reports a junction: ``os.lstat`` gives a directory with the
reparse-point attribute and the mount-point reparse tag, not a link, and
``os.path.realpath`` resolves it to where it leads. Each cell asks twice, with
the outside directory holding the name and without it.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path
from typing import Any, Callable, Dict

import pytest

pytestmark = pytest.mark.unit

SESSION = "client-one"
OUTSIDE_CONFIG = "project_name: outside\n"
OUTSIDE_POLICY = "workspace:\n  max_severity_threshold: LOW\n"
#: IO_REPARSE_TAG_MOUNT_POINT, the reparse tag of a junction.
MOUNT_POINT_TAG = 0xA0000003


class _JunctionStat:
    """The stat of the directory a junction leads to, as lstat reports a junction."""

    def __init__(self, target: os.stat_result) -> None:
        self._target = target
        self.st_file_attributes = stat.FILE_ATTRIBUTE_REPARSE_POINT
        self.st_reparse_tag = MOUNT_POINT_TAG

    def __getattr__(self, name: str) -> Any:
        return getattr(self._target, name)


def _as_a_junction(
    monkeypatch: pytest.MonkeyPatch, junction: Path, outside: Path
) -> None:
    real_lstat = os.lstat
    real_stat = os.stat
    real_realpath = os.path.realpath
    shown = str(junction)
    target = str(outside)

    def lstat(path: Any, *args: Any, **kwargs: Any) -> Any:
        if os.fspath(path) == shown and not args and not kwargs:
            return _JunctionStat(real_stat(shown))
        return real_lstat(path, *args, **kwargs)

    def stat(path: Any, *args: Any, **kwargs: Any) -> Any:
        # pathlib's lstat and is_symlink go through os.stat with
        # follow_symlinks=False on some interpreters, so the junction has to
        # read the same there as through os.lstat.
        if (
            os.fspath(path) == shown
            and not args
            and kwargs.get("follow_symlinks") is False
            and kwargs.get("dir_fd") is None
        ):
            return _JunctionStat(real_stat(shown))
        return real_stat(path, *args, **kwargs)

    def realpath(path: Any, *args: Any, **kwargs: Any) -> Any:
        text = os.fspath(path)
        if text == shown or text.startswith(shown + os.sep):
            return target + text[len(shown) :]
        return real_realpath(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(os, "stat", stat)
    monkeypatch.setattr(os.path, "realpath", realpath)
    # Older pathlib binds the os functions it reads ONCE, at import, on its
    # accessor object, so patching the os modules alone leaves Path.stat,
    # Path.is_symlink and Path.resolve reading the real symlink: the stand-in
    # never reads as a junction there, and the resolve walk, which asks
    # ``islink`` through the patched lstat and is told "no link", stops at the
    # junction instead of following it to where it leads. Keyed on each
    # attribute, never the version: the accessor is gone from newer
    # interpreters, where the patches above are the ones pathlib reads, and
    # which methods it carries differs between the interpreters that have it.
    import pathlib as pathlib_module

    accessor = getattr(pathlib_module, "_normal_accessor", None)
    if accessor is not None:
        # Path.lstat there is stat(follow_symlinks=False), so one accessor
        # method serves both; an accessor with its own lstat gets it too.
        monkeypatch.setattr(accessor, "stat", stat)
        for name, wrapper in (("lstat", lstat), ("realpath", realpath)):
            if hasattr(accessor, name):
                monkeypatch.setattr(accessor, name, wrapper)


@pytest.fixture
def roots(tmp_path, monkeypatch) -> Dict[str, Path]:
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    root = tmp_path / "ws"
    project = root / "app"
    project.mkdir(parents=True)
    (project / "app.py").write_text("x = 1\n", encoding="utf-8")
    workspace_file = root / "dev.code-workspace"
    workspace_file.write_text(
        json.dumps({"folders": [{"path": "app"}]}), encoding="utf-8"
    )
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(root))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.setattr(
        scan_registry_module, "_scan_registry", scan_registry_module.ScanRegistry()
    )
    return {"tmp": tmp_path, "root": root, "project": project, "ws": workspace_file}


def _fresh(roots: Dict[str, Path], held: bool) -> Dict[str, Path]:
    """A copy of the tree per run, so each run has its own ``.ash``."""
    import shutil

    base = roots["tmp"] / ("run-held" if held else "run-empty")
    base.mkdir()
    root = base / "ws"
    shutil.copytree(roots["root"], root)
    return {
        "tmp": base,
        "root": root,
        "project": root / "app",
        "ws": root / "dev.code-workspace",
    }


def _junction_out(
    monkeypatch: pytest.MonkeyPatch,
    directory: Path,
    tmp: Path,
    name: str,
    text: str,
    held: bool,
) -> None:
    """``directory/.ash``, a junction to an outside directory holding ``name`` or not."""
    outside = tmp / ("outside-holding" if held else "outside-empty")
    outside.mkdir()
    if held:
        (outside / name).write_text(text, encoding="utf-8")
    junction = directory / ".ash"
    # Something has to lead there on this platform; lstat then says it is no link.
    junction.symlink_to(outside, target_is_directory=True)
    _as_a_junction(monkeypatch, junction, outside)


def _without(response: Any, *paths: Path) -> str:
    text = json.dumps(response, default=str, sort_keys=True)
    for path in paths:
        text = text.replace(str(path), "<tree>")
    return text


def _same_both_ways(ask: Callable[[bool], Any]) -> Any:
    held, empty = ask(True), ask(False)
    assert held == empty, (held, empty)
    return held


def test_the_stand_in_reads_as_a_junction(roots, monkeypatch) -> None:
    """Control: what the cells build is no link to ``Path.is_symlink``."""
    tree = _fresh(roots, True)
    _junction_out(
        monkeypatch, tree["project"], tree["tmp"], ".ash.yaml", OUTSIDE_CONFIG, True
    )
    junction = tree["project"] / ".ash"

    assert not junction.is_symlink()
    assert not stat.S_ISLNK(os.lstat(junction).st_mode)
    assert os.path.realpath(junction) == str(tree["tmp"] / "outside-holding")


def test_config_discovery_in_a_scan_target(roots, monkeypatch) -> None:
    from automated_security_helper.cli.mcp.sandbox import validate_discovered_config

    def ask(held: bool) -> Any:
        with monkeypatch.context() as patch:
            tree = _fresh(roots, held)
            patch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tree["root"]))
            _junction_out(
                patch, tree["project"], tree["tmp"], ".ash.yaml", OUTSIDE_CONFIG, held
            )
            refusal = validate_discovered_config(tree["project"], SESSION)
            return None if refusal is None else _without(str(refusal), tree["root"])

    answer = _same_both_ways(ask)
    assert answer is not None, "a junction at .ash out of the roots was not refused"


def test_workspace_policy_discovery(roots, monkeypatch) -> None:
    from automated_security_helper.cli.mcp.workspace import mcp_resolve_workspace

    def ask(held: bool) -> Any:
        with monkeypatch.context() as patch:
            tree = _fresh(roots, held)
            patch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tree["root"]))
            _junction_out(
                patch,
                tree["root"],
                tree["tmp"],
                "ash-workspace.yaml",
                OUTSIDE_POLICY,
                held,
            )
            response = asyncio.run(
                mcp_resolve_workspace(
                    workspace_file=str(tree["ws"]), session_id=SESSION
                )
            )
            return _without(response, tree["root"])

    answer = _same_both_ways(ask)
    assert '"error_type": "config_input_not_permitted"' in answer, answer
    assert '"exit_code": 3' in answer, answer
