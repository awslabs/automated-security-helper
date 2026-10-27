# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The environment ``run_ended_with_the_server`` gives its child is built like the
other spawn helpers'.

Why this file exists
--------------------
``_spawn_env`` (``child_environ``) is the one place that decides what environment a
child starts with: a copy of ours, never ``None``; PATH with its in-tree and not
anchored entries taken off and never empty; and, while ASH is offline, the variables
that turn off each tool's own update and telemetry checks. ``spawn_run`` and the
``run_command`` family build their child's environment through it.

``run_ended_with_the_server`` passed its keyword arguments to ``_run_cancellable`` as
they were, so the child got the caller's ``env`` unchanged:

- a ``PATH=""`` reached the child empty, which it reads as the working directory;
- an in-tree PATH entry stayed on the child's PATH;
- the offline tool variables were missing in offline mode;
- a call that passed no ``env`` gave Popen ``env=None``, the spawn against the live
  ``environ`` array that ``_spawn_env`` exists to avoid.

Each cell reads the keyword arguments Popen is given. Popen is replaced by a recorder
that returns a stand-in for a child that has exited; no process is started.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.offline_tool_env import OFFLINE_TOOL_ENVIRONMENT
from automated_security_helper.utils.scanned_tree import is_inside_tree
from automated_security_helper.utils.subprocess_utils import (
    ALLOW_IN_TREE_TOOLS_ENV,
    child_environ,
    run_ended_with_the_server,
    scanning_tree,
)

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX default directories"
)

#: Outside a scan, and inside one with a scanned tree.
SCOPES = ["no-scan", "scan"]

#: Stands for a call that passes no ``env``.
_NO_ENV: Any = object()


class _Child:
    """A stand-in for a child that has exited 0. No process is behind it."""

    pid = 2**30 + 2003
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
def online(monkeypatch):
    """ASH online, and the in-tree opt-in off, unless a cell says otherwise."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.delenv(ALLOW_IN_TREE_TOOLS_ENV, raising=False)


@pytest.fixture(autouse=True)
def _unresolved_names_reach_the_mocked_spawn(monkeypatch):
    """Hand a name that resolves nowhere to the recorder on every platform.

    These cells pass the bare name ``tool`` to a recorder in place of Popen. On
    Windows ASH refuses a bare name it cannot resolve before it spawns it, as every
    spawn helper does (subprocess_utils._refuse_unresolved_on_windows). The cells
    are about the environment the child gets, so that decision is set aside here.
    """
    monkeypatch.setattr(subprocess_utils, "_refuse_unresolved_on_windows", False)


@pytest.fixture
def repo(tmp_path, monkeypatch) -> Path:
    """The scanned tree, and ASH's working directory, as ``cd repo && ash scan``."""
    tree = tmp_path / "repo"
    tree.mkdir()
    monkeypatch.chdir(tree)
    return tree


@pytest.fixture
def started(monkeypatch) -> List[Tuple[List[str], Dict[str, Any]]]:
    """Popen replaced by a recorder: each start's argv and keyword arguments.

    The group registry is a fresh one, so no other test's record is met.
    """
    monkeypatch.setattr(subprocess_utils, "_RUNNING_GROUPS", {})
    monkeypatch.setattr(subprocess_utils, "_STOPPING", False)
    monkeypatch.setattr(subprocess_utils, "_SPAWNS_STARTING", 0)
    starts: List[Tuple[List[str], Dict[str, Any]]] = []

    def popen(args, **kwargs):
        starts.append((list(args), kwargs))
        return _Child()

    monkeypatch.setattr(subprocess, "Popen", popen)
    return starts


def _run(repo: Path, scope: str, env: Any = _NO_ENV) -> Optional[Dict[str, str]]:
    """Run the helper once, as a scan with ``scope`` would, and return what
    ``child_environ`` builds for the same input in the same scope."""
    call: Dict[str, Any] = {} if env is _NO_ENV else {"env": env}

    def once() -> Dict[str, str]:
        result = run_ended_with_the_server(["tool"], **call)
        assert result.returncode == 0
        return child_environ(None if env is _NO_ENV else env)

    if scope == "scan":
        with scanning_tree(repo):
            return once()
    return once()


def _env_the_child_got(started) -> Optional[Dict[str, str]]:
    assert len(started) == 1, f"the helper made {len(started)} starts: {started}"
    argv, kwargs = started[0]
    assert argv == ["tool"]
    return kwargs.get("env")


def _entries(env: Dict[str, str]) -> List[str]:
    return env["PATH"].split(os.pathsep)


# ---------------------------------------------------------------------------
# PATH
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scope", SCOPES)
def test_a_path_the_caller_set_to_empty_does_not_reach_the_child_empty(
    started, repo, scope
):
    _run(repo, scope, {"PATH": ""})

    env = _env_the_child_got(started)
    assert env is not None
    assert env["PATH"] != "", "an empty PATH is read as the working directory"
    not_anchored = [
        entry
        for entry in _entries(env)
        if not (entry and subprocess_utils._is_anchored(entry))
    ]
    assert not not_anchored, (
        f"entries that depend on the working directory: {not_anchored}"
    )


@posix_only
def test_an_in_tree_path_entry_is_dropped_from_the_childs_path(started, repo):
    in_tree = str(repo / ".venv" / "bin")
    given = os.pathsep.join([in_tree, "/usr/bin"])

    _run(repo, "scan", {"PATH": given})

    env = _env_the_child_got(started)
    assert env is not None
    assert [e for e in _entries(env) if is_inside_tree(e, str(repo))] == [], (
        "the child would find the scanned tree's own tools by name"
    )
    assert _entries(env) == ["/usr/bin"]


# ---------------------------------------------------------------------------
# The offline tool variables
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scope", SCOPES)
def test_offline_mode_gives_the_child_the_offline_tool_variables(
    started, repo, monkeypatch, scope
):
    monkeypatch.setenv("ASH_OFFLINE", "true")

    _run(repo, scope, {"ASH_TEST_UNRELATED": "kept"})

    env = _env_the_child_got(started)
    assert env is not None
    missing = {
        name: value
        for name, value in OFFLINE_TOOL_ENVIRONMENT.items()
        if env.get(name) != value
    }
    assert missing == {}, "the child would run its update and telemetry checks"


# ---------------------------------------------------------------------------
# The same answer as _spawn_env, whatever the input
# ---------------------------------------------------------------------------


def _given(case: str, repo: Path) -> Any:
    return {
        "empty-path": {"PATH": ""},
        "relative-and-empty-entries": {
            "PATH": os.pathsep.join(["bin", "", "/usr/bin"])
        },
        "in-tree-entry": {
            "PATH": os.pathsep.join([str(repo / ".venv" / "bin"), "/usr/bin"])
        },
        "offline-mode": {"ASH_TEST_UNRELATED": "kept"},
        "no-env": _NO_ENV,
    }[case]


@pytest.mark.parametrize("scope", SCOPES)
@pytest.mark.parametrize(
    "case",
    [
        "empty-path",
        "relative-and-empty-entries",
        "in-tree-entry",
        "offline-mode",
        "no-env",
    ],
)
def test_the_child_gets_what_spawn_env_builds_for_the_same_input(
    started, repo, monkeypatch, scope, case
):
    if case == "offline-mode":
        monkeypatch.setenv("ASH_OFFLINE", "true")

    expected = _run(repo, scope, _given(case, repo))

    env = _env_the_child_got(started)
    assert isinstance(env, dict), (
        f"Popen was given env={env!r}: the child starts against the live environ"
    )
    assert env == expected


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scope", SCOPES)
def test_control_an_unrelated_variable_is_handed_over_as_it_is(started, repo, scope):
    _run(repo, scope, {"ASH_TEST_UNRELATED": "kept value"})

    env = _env_the_child_got(started)
    assert env is not None
    assert env["ASH_TEST_UNRELATED"] == "kept value"
    assert "PATH" not in env, "a PATH that is not set stays unset"


@posix_only
@pytest.mark.parametrize("scope", SCOPES)
def test_control_an_anchored_path_is_handed_over_as_it_is(started, repo, scope):
    given = os.pathsep.join(["/usr/bin", "/bin"])

    _run(repo, scope, {"PATH": given})

    env = _env_the_child_got(started)
    assert env is not None
    assert env["PATH"] == given


def test_control_online_mode_adds_no_offline_variable(started, repo):
    _run(repo, "no-scan", {"ASH_TEST_UNRELATED": "kept"})

    env = _env_the_child_got(started)
    assert env is not None
    assert [name for name in OFFLINE_TOOL_ENVIRONMENT if name in env] == []


def test_control_the_callers_own_dict_is_left_as_it_was(started, repo):
    given = {"PATH": "", "ASH_TEST_UNRELATED": "kept"}
    before = dict(given)

    _run(repo, "scan", given)

    assert given == before
