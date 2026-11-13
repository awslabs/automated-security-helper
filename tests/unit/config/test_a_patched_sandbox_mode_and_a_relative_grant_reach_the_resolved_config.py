# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A patched sandbox mode and a relative grant reach the resolved config.

A root config outside every checkout that extends a base inside the scanned
checkout keeps the sandbox settings it writes itself (``_with_own_sandbox``). Three
places apply that rule, one for each way the root is named: as the selected
``--config``, as the file ``ASH_CONFIG`` names, and as the operator's trusted
config. Until now the visible result of the root's own ``patch`` on its sandbox
mode was tested only through the private helpers. These cells drive
``resolve_config``:

- a root that writes ``bwrap`` and patches the mode to another one ends with that
  mode, and a ``remove`` of the mode leaves the floor the operator's other files
  carry (here ``ASH_CONFIG``'s) in place;
- a relative ``extra_read_paths`` entry of the root is taken from the root's
  directory at all three, whether the root extends a base (the own section) or
  not (the loader), which includes the ``ASH_CONFIG`` load (``get_default_config``).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
import yaml

from automated_security_helper.config.resolve_config import resolve_config
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

SITES = ["the-selected-config", "the-file-ASH_CONFIG-names", "the-trusted-config"]


def _op(op: str, path: str, value: Any = None) -> Dict[str, Any]:
    operation: Dict[str, Any] = {"op": op, "path": path}
    if op != "remove":
        operation["value"] = value
    return operation


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    # ASH_CONFIG would add a file of its own to the resolution, and a basetemp
    # inside a checkout would put every layout inside that checkout too. A
    # workspace root of the MCP server that holds the basetemp would make every
    # file here a client's, so it is pointed at a directory nothing is in.
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    for directory in (tmp_path, *tmp_path.parents):
        assert not os.path.lexists(directory / ".git"), (
            f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
        )


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _scanned_checkout(w: Path) -> Path:
    """W/repo, a checkout with a config of its own and a base the root extends."""
    repo = w / "repo"
    mark_git_checkout(repo)
    _write(repo / "a.py", "x = 1\n")
    _write(repo / ".ash" / ".ash.yaml", "project_name: repository\n")
    _write(repo / ".ash" / "base.yaml", "project_name: base\n")
    return repo


def _root(w: Path, sandbox: Dict[str, Any], patch: List[Any], extends: bool = True):
    document: Dict[str, Any] = {}
    if extends:
        document["extends"] = "repo/.ash/base.yaml"
    document["sandbox"] = sandbox
    if patch:
        document["patch"] = patch
    return _write(w / "operator.yaml", yaml.safe_dump(document, sort_keys=False))


def _resolved_sandbox(
    site: str,
    operator: Path,
    repo: Path,
    monkeypatch,
    floor: Optional[Path] = None,
):
    """The sandbox the root resolves to at *site*. *floor* is a file outside every
    checkout that ASH_CONFIG names where the root is the selected config."""
    if site == "the-selected-config":
        if floor is not None:
            monkeypatch.setenv("ASH_CONFIG", str(floor))
        return resolve_config(config_path=operator, source_dir=repo).sandbox
    if site == "the-file-ASH_CONFIG-names":
        monkeypatch.setenv("ASH_CONFIG", str(operator))
        return resolve_config(source_dir=repo).sandbox
    return resolve_config(source_dir=repo, trusted_config_path=operator).sandbox


@pytest.mark.parametrize("site", SITES)
def test_a_mode_the_roots_patch_replaces_is_the_mode_it_resolves_to(
    site, tmp_path, monkeypatch
):
    w = tmp_path / "W"
    repo = _scanned_checkout(w)
    operator = _root(
        w, {"mode": "bwrap"}, [_op("replace", "/sandbox/mode", "firejail")]
    )

    sandbox = _resolved_sandbox(site, operator, repo, monkeypatch)

    assert sandbox.mode == "firejail"


def test_a_mode_the_roots_patch_turns_off_over_a_floor_is_off(tmp_path, monkeypatch):
    """The root is the operator's own file, so its choice stands over the floor
    ASH_CONFIG sets."""
    w = tmp_path / "W"
    repo = _scanned_checkout(w)
    floor = _write(w / "floor.yaml", "sandbox:\n  mode: bwrap\n")
    operator = _root(w, {"mode": "bwrap"}, [_op("replace", "/sandbox/mode", "off")])

    sandbox = _resolved_sandbox(
        "the-selected-config", operator, repo, monkeypatch, floor=floor
    )

    assert sandbox.mode == "off"


def test_a_mode_the_roots_patch_removes_leaves_the_floor_in_place(
    tmp_path, monkeypatch
):
    w = tmp_path / "W"
    repo = _scanned_checkout(w)
    floor = _write(w / "floor.yaml", "sandbox:\n  mode: bwrap\n")
    operator = _root(w, {"mode": "firejail"}, [_op("remove", "/sandbox/mode")])

    sandbox = _resolved_sandbox(
        "the-selected-config", operator, repo, monkeypatch, floor=floor
    )

    assert sandbox.mode == "bwrap"


@pytest.mark.parametrize("site", ["the-file-ASH_CONFIG-names", "the-trusted-config"])
def test_a_mode_the_roots_patch_removes_leaves_no_mode_of_the_roots(
    site, tmp_path, monkeypatch
):
    """Nothing else carries a mode here, so the removal leaves the default."""
    w = tmp_path / "W"
    repo = _scanned_checkout(w)
    operator = _root(w, {"mode": "firejail"}, [_op("remove", "/sandbox/mode")])

    sandbox = _resolved_sandbox(site, operator, repo, monkeypatch)

    assert sandbox.mode == "off"


@pytest.mark.parametrize("extends", [True, False], ids=["extends-a-base", "no-extends"])
@pytest.mark.parametrize("site", SITES)
def test_a_relative_extra_read_path_is_taken_from_the_roots_directory(
    site, extends, tmp_path, monkeypatch
):
    w = tmp_path / "W"
    repo = _scanned_checkout(w)
    operator = _root(w, {"extra_read_paths": ["rel/dir"]}, [], extends=extends)

    sandbox = _resolved_sandbox(site, operator, repo, monkeypatch)

    assert list(sandbox.extra_read_paths) == [str((w / "rel" / "dir").resolve())]
