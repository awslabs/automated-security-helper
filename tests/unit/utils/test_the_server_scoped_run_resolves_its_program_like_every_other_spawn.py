# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The program ``run_ended_with_the_server`` starts is resolved like the other spawn
helpers' programs.

Why this file exists
--------------------
Before a spawn helper starts a child it points ``args[0]`` at the file
``find_executable`` finds for it, and refuses a program that would come from the
working directory or the scanned tree (``_resolve_for_spawn``): a path relative to
the working directory, a bare name only the working directory supplies, and a copy
found only inside the scanned tree during a scan. ``spawn_run`` and the
``run_command`` family all do this, and raise or report the ``FileNotFoundError``
that ``subprocess.run`` raises for a program that is not installed.

``run_ended_with_the_server`` passed its argv to ``_run_cancellable`` as it was, so
the same program got a different answer there:

- a bare name reached Popen as a bare name, and the child's own PATH search chose
  the file;
- ``./bin/tool`` reached Popen, which starts it from the working directory;
- an absolute path inside the scanned tree reached Popen during a scan;
- a bare name that only the working directory or the scanned tree supplies
  reached Popen unrefused.

Each cell reads the argv Popen is given, or the error the helper raises before it
gets that far. Popen is replaced by a recorder that returns a stand-in for a child
that has exited, and the tools the cells plant are never run. The cells are POSIX
only: they plant executable files.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Tuple

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.subprocess_utils import (
    ALLOW_IN_TREE_TOOLS_ENV,
    run_ended_with_the_server,
    scanning_tree,
)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="the planted tools are POSIX executable files"
)

#: A tool name no installed program has.
TOOL = "ash-resolve-probe"

#: Outside a scan, and inside one that scans the repository.
SCOPES = ["no-scan", "scan"]


class _Child:
    """A stand-in for a child that has exited 0. No process is behind it."""

    pid = 2**30 + 2005
    returncode = 0
    args = ["tool"]
    stdin = None
    stdout = None
    stderr = None

    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0

    def communicate(self, *args, **kwargs):
        return "", ""


@pytest.fixture(autouse=True)
def in_tree_tools_off(monkeypatch):
    """The operator's opt-in to run tools from the scanned tree is off."""
    monkeypatch.delenv(ALLOW_IN_TREE_TOOLS_ENV, raising=False)


@pytest.fixture
def tree(tmp_path, monkeypatch):
    """The scanned repository as the working directory, and an absolute directory
    outside it.

    ASH's own bin directories are pointed at an empty directory, so a tool is found
    only through the PATH each cell sets.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    ash_bin = tmp_path / "ash-bin"
    ash_bin.mkdir()
    monkeypatch.chdir(repo)
    monkeypatch.setenv("ASH_BIN_PATH", str(ash_bin))
    monkeypatch.setattr(subprocess_utils, "path_independent_dirs", lambda: [ash_bin])
    subprocess_utils.clear_find_executable_cache()
    yield SimpleNamespace(root=tmp_path, repo=repo, outside=outside)
    subprocess_utils.clear_find_executable_cache()


@pytest.fixture
def started(monkeypatch) -> List[Tuple[Any, Dict[str, Any]]]:
    """Popen replaced by a recorder: each start's argv, as given, and keyword arguments.

    The group registry is a fresh one, so no other test's record is met.
    """
    monkeypatch.setattr(subprocess_utils, "_RUNNING_GROUPS", {})
    monkeypatch.setattr(subprocess_utils, "_STOPPING", False)
    monkeypatch.setattr(subprocess_utils, "_SPAWNS_STARTING", 0)
    starts: List[Tuple[Any, Dict[str, Any]]] = []

    def popen(args, **kwargs):
        starts.append((args, kwargs))
        return _Child()

    monkeypatch.setattr(subprocess, "Popen", popen)
    return starts


def _plant(directory: Path, name: str) -> Path:
    """An executable file ``name`` in ``directory``. Nothing runs it: Popen is replaced."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _run(tree, scope: str, argv: Any, **kwargs: Any) -> subprocess.CompletedProcess:
    """Run the helper once, outside a scan or inside one that scans the repository."""
    if scope == "scan":
        with scanning_tree(tree.repo):
            return run_ended_with_the_server(argv, **kwargs)
    return run_ended_with_the_server(argv, **kwargs)


def _argv_the_child_got(started) -> Any:
    assert len(started) == 1, f"the helper made {len(started)} starts: {started}"
    return started[0][0]


# ---------------------------------------------------------------------------
# A program the other spawn helpers rewrite or refuse
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scope", SCOPES)
def test_a_bare_name_is_started_as_the_file_it_resolves_to(
    started, tree, monkeypatch, scope
):
    planted = _plant(tree.outside, TOOL)
    monkeypatch.setenv("PATH", str(tree.outside))

    _run(tree, scope, [TOOL, "--version"])

    assert _argv_the_child_got(started) == [str(planted), "--version"], (
        "the child looks the bare name up itself"
    )


@pytest.mark.parametrize("spelling", ["dot-slash", "bare-directory"])
def test_a_program_path_relative_to_the_working_directory_is_refused(
    started, tree, monkeypatch, spelling
):
    _plant(tree.repo / "bin", TOOL)
    monkeypatch.setenv("PATH", str(tree.outside))
    program = f"./bin/{TOOL}" if spelling == "dot-slash" else f"bin/{TOOL}"

    with pytest.raises(FileNotFoundError, match="relative to the working directory"):
        run_ended_with_the_server([program, "--version"])

    assert started == [], "the child was started"


#: PATH as entries, and the directory under the repository that the entry that is
#: not absolute names. "{outside}" is replaced by the absolute directory.
LAYOUTS = {
    "relative-entry": (["bin", "{outside}"], "bin"),
    "leading-empty-entry": (["", "{outside}"], "."),
}


@pytest.mark.parametrize("where", ["ash-cwd", "child-cwd"])
@pytest.mark.parametrize("layout", sorted(LAYOUTS))
def test_a_tool_only_the_working_directory_supplies_is_refused(
    started, tree, monkeypatch, layout, where
):
    """``child-cwd`` runs ASH from elsewhere and gives the tool the repository as
    its working directory: the child's own search reads a relative entry there."""
    entries, holder = LAYOUTS[layout]
    path_value = os.pathsep.join(e.format(outside=tree.outside) for e in entries)
    monkeypatch.setenv("PATH", path_value)
    _plant(tree.repo / holder, TOOL)
    call: Dict[str, Any] = {}
    if where == "child-cwd":
        elsewhere = tree.root / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        call["cwd"] = tree.repo

    with pytest.raises(FileNotFoundError, match="through the working directory"):
        run_ended_with_the_server([TOOL, "--version"], **call)

    assert started == [], "the child was started"


@pytest.mark.parametrize("program", ["bare", "absolute"])
def test_a_tool_found_only_inside_the_scanned_tree_is_refused(
    started, tree, monkeypatch, program
):
    in_tree = _plant(tree.repo / ".venv" / "bin", TOOL)
    monkeypatch.setenv(
        "PATH", os.pathsep.join([str(in_tree.parent), str(tree.outside)])
    )
    name = TOOL if program == "bare" else str(in_tree)

    with scanning_tree(tree.repo):
        with pytest.raises(
            FileNotFoundError, match="found only inside the scanned tree"
        ):
            run_ended_with_the_server([name, "--version"])

    assert started == [], "the child was started"


# ---------------------------------------------------------------------------
# Controls: a program the other spawn helpers pass on as it is
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scope", SCOPES)
@pytest.mark.parametrize("file", ["an-executable-file", "a-missing-file"])
def test_control_an_absolute_program_path_is_handed_over_as_it_is(
    started, tree, monkeypatch, scope, file
):
    """A missing file is the OS's to report, as the converter's launch expects."""
    if file == "an-executable-file":
        program = _plant(tree.outside, TOOL)
    else:
        program = tree.outside / "missing"
    monkeypatch.setenv("PATH", "/usr/bin")
    argv = [str(program), "--flag", "value"]

    _run(tree, scope, list(argv))

    assert _argv_the_child_got(started) == argv


@pytest.mark.parametrize("scope", SCOPES)
def test_control_the_jupyter_converters_launch_is_handed_over_as_it_is(
    started, tree, monkeypatch, scope
):
    """The argv and keyword arguments of the converter's unsandboxed nbconvert run."""
    nbconvert = _plant(tree.outside, "jupyter-nbconvert")
    staging = tree.root / "staging"
    staging.mkdir()
    notebook = staging / "notebook.ipynb"
    argv = [
        str(nbconvert),
        "--log-level",
        "WARN",
        "--to",
        "python",
        str(notebook),
        "--output",
        notebook.stem,
        "--output-dir",
        str(tree.root / "out"),
    ]
    monkeypatch.setenv("PATH", "/usr/bin")

    _run(
        tree,
        scope,
        list(argv),
        capture_output=True,
        stdin=subprocess.DEVNULL,
        text=True,
        timeout=60,
        cwd=staging,
        env=snapshot_environ(),
    )

    assert _argv_the_child_got(started) == argv


@pytest.mark.parametrize("scope", SCOPES)
def test_control_a_name_nothing_supplies_is_passed_on_as_it_was(
    started, tree, monkeypatch, scope
):
    """Not found, and not through the working directory or the tree either: left to
    the OS to start or fail on, as the other helpers leave it on POSIX."""
    monkeypatch.setenv("PATH", str(tree.outside))
    argv = ["ash-resolve-no-such-tool", "--version"]

    _run(tree, scope, list(argv))

    assert _argv_the_child_got(started) == argv


def test_control_the_callers_own_list_is_left_as_it_was(started, tree, monkeypatch):
    _plant(tree.outside, TOOL)
    monkeypatch.setenv("PATH", str(tree.outside))
    given = [TOOL, "--version"]

    run_ended_with_the_server(given)

    assert given == [TOOL, "--version"]


def test_control_a_shell_command_is_not_resolved(started, tree, monkeypatch):
    _plant(tree.outside, TOOL)
    monkeypatch.setenv("PATH", str(tree.outside))
    command = f"{TOOL} --version"

    run_ended_with_the_server(command, shell=True)

    assert _argv_the_child_got(started) == command
