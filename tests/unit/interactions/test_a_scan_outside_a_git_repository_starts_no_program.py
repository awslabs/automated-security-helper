# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan of a directory outside every git repository starts no program.

A scan records where it looked as ``metadata.scan_source``: the scanned directory
relative to the root of its git repository, or its absolute path outside one
(utils/scan_source.py). git finds a repository only through a ``.git`` entry in the
directory or one of its parents, or through the environment, so with neither there
is no repository to ask git about, and the scan records the absolute path without
starting git.

Where git could find a repository, it is still asked for the root:

- a ``.git`` directory in the scanned directory or in a parent;
- a ``.git`` file there, as a linked worktree has;
- GIT_DIR or GIT_WORK_TREE in the environment, with no ``.git`` entry;
- a ``.git`` entry in a parent that cannot be listed: seeing the entry needs only
  the search permission that reaching the scanned directory needs too;
- a parent whose ``.git`` entry cannot be checked, which is no proof that there is
  none.

Here git cannot answer (its start is refused), and the scan records the absolute
path, as it does for any directory git gives no root for.

Each cell runs ``ash scan`` in a child process with the driver of
test_a_name_that_is_not_utf8_keeps_the_results_file.py: every tool probe is answered
as on a host without the tool, and every program start but ASH's detect-secrets
worker is refused and logged, so a git start is seen and never runs. A ``git`` that
exits at once and writes nothing is also first on PATH.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 - the CLI under test runs as a child process
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest

from tests.unit.interactions import (
    test_a_name_that_is_not_utf8_keeps_the_results_file as base,
)
from tests.utils.helpers import checkout_env
from tests.utils.isolated_tool_env import network_containment

#: Variables that point git at a repository whatever its working directory is.
#: Left out of the child's environment unless a cell sets one.
_GIT_LOCATION = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR")

#: Run before the driver. A stat of the one path ASH_TEST_DENY_LOOKUP names raises
#: PermissionError, as where a filesystem or a security module refuses to say.
_DENY_LOOKUP = """\
import os as _os
import sys as _sys

_DENIED = _os.environ.get("ASH_TEST_DENY_LOOKUP")
if _DENIED:
    # On 3.10, pathlib copies os.stat into _NormalAccessor at ITS import, so
    # the deny reaches pathlib stats only when this prelude runs first. A
    # pathlib imported earlier (a .pth hook, a coverage bootstrap) would
    # bypass the deny silently; fail loudly instead.
    assert "pathlib" not in _sys.modules, (
        "the deny must be installed before pathlib is first imported"
    )

    class _Denying:
        # A class with __call__ and no __get__ is not a descriptor, so
        # 3.10's _NormalAccessor copy never binds it as a method: the call
        # shape is (path, *args) on every interpreter, with no argument
        # guessing, and a path-less call such as os.stat(None) keeps the
        # real function's own error.
        def __init__(self, real):
            self._real = real

        def __call__(self, path, *args, **kwargs):
            if isinstance(path, (str, bytes, _os.PathLike)) and _os.path.abspath(
                _os.fsdecode(_os.fspath(path))
            ) == _DENIED:
                raise PermissionError(13, "refused by the test", _DENIED)
            return self._real(path, *args, **kwargs)

    _os.stat = _Denying(_os.stat)
    _os.lstat = _Denying(_os.lstat)
"""


def _stub_git_dir(tmp_path: Path) -> Path:
    """A directory holding a ``git`` that exits at once and writes nothing."""
    stub_dir = tmp_path / "stub-bin"
    stub_dir.mkdir(exist_ok=True)
    git = stub_dir / "git"
    git.write_text("#!/bin/sh\nexit 97\n", encoding="utf-8")
    git.chmod(0o755)
    return stub_dir


def _scan(
    tmp_path: Path,
    source: Path,
    extra_env: Optional[Dict[str, str]] = None,
    deny: Optional[Path] = None,
) -> Tuple[int, str, Path, List[str]]:
    """``ash scan`` of *source* in a child that starts no program but ASH's
    detect-secrets worker, with the starts it tried, as the driver logged them."""
    output = tmp_path / f"{source.name}-out"
    starts = tmp_path / f"{source.name}-starts.log"
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("ASH_") and key not in _GIT_LOCATION
    }
    env.update(network_containment())
    env.update(
        HOME=str(home),
        XDG_CONFIG_HOME=str(home / ".config"),
        XDG_CACHE_HOME=str(home / ".cache"),
        XDG_DATA_HOME=str(home / ".local" / "share"),
        XDG_STATE_HOME=str(home / ".local" / "state"),
        PATH=os.pathsep.join([str(_stub_git_dir(tmp_path)), env.get("PATH", "")]),
        PYTHONIOENCODING="utf-8:strict",
        ASH_TEST_START_LOG=str(starts),
        COLUMNS="1000",
    )
    if deny is not None:
        env["ASH_TEST_DENY_LOOKUP"] = str(deny)
    env.update(extra_env or {})
    # The child imports ASH from this checkout: it runs without -I, which would
    # ignore PYTHONPATH, and checkout_env puts the checkout first on it.
    child = subprocess.run(  # nosec B603 - fixed interpreter and arguments
        [
            sys.executable,
            "-c",
            _DENY_LOOKUP + base._DRIVER,
            "scan",
            "--mode",
            "local",
            "--source-dir",
            str(source),
            "--output-dir",
            str(output),
            "--scanners",
            "detect-secrets",
            "--python-only",
            "--no-progress",
            "--no-color",
        ],
        cwd=tmp_path,
        env=checkout_env(env),
        capture_output=True,
        timeout=600,
    )
    said = child.stdout.decode("utf-8", "backslashreplace") + child.stderr.decode(
        "utf-8", "backslashreplace"
    )
    started = starts.read_text(encoding="utf-8").splitlines() if starts.exists() else []
    return child.returncode, said, output, started


def _plain_tree(root: Path) -> Path:
    """*root*, made, holding one file detect-secrets reports, resolved."""
    return base._tree(root, {base._PLAIN: base._SECRET}).resolve()


def _outside_every_repository(source: Path) -> None:
    for directory in (source, *source.parents):
        if os.path.lexists(directory / ".git"):
            pytest.skip(f"{directory} holds a .git entry, so {source} is in one here")


def _root_lookups(started: List[str], source: Path) -> List[str]:
    """The refused starts of ``git rev-parse --show-toplevel`` in *source*."""
    return [
        line
        for line in started
        if "'rev-parse', '--show-toplevel'" in line and str(source) in line
    ]


def _recorded_scan_source(output: Path) -> object:
    with open(output / "ash_aggregated_results.json", "rb") as handle:
        results = json.loads(handle.read().decode("utf-8"))
    return (results.get("metadata") or {}).get("scan_source")


def test_a_scan_outside_every_repository_starts_no_program(tmp_path):
    source = _plain_tree(tmp_path / "plain")
    _outside_every_repository(source)

    code, said, output, started = _scan(tmp_path, source)

    assert code == 2, said
    assert started == [], started
    # The form scan_source takes outside a repository: the absolute path.
    assert _recorded_scan_source(output) == source.as_posix(), said


def _repository_tree(tmp_path: Path, shape: str) -> Path:
    top = tmp_path / shape
    if shape == "git-directory-in-a-parent":
        (top / ".git").mkdir(parents=True)
        return _plain_tree(top / "services" / "api")
    source = _plain_tree(top)
    if shape == "git-directory":
        (source / ".git").mkdir()
    else:
        (source / ".git").write_text(
            "gitdir: /nonexistent/.git/worktrees/api\n", encoding="utf-8"
        )
    return source


@pytest.mark.parametrize(
    "shape", ["git-directory", "git-file", "git-directory-in-a-parent"]
)
def test_a_scan_with_a_git_entry_still_asks_git_for_the_root(tmp_path, shape):
    """The positive control: where git could find a repository, it is asked."""
    source = _repository_tree(tmp_path, shape)

    code, said, output, started = _scan(tmp_path, source)

    assert code == 2, said
    assert (output / "ash_aggregated_results.json").is_file(), said
    assert _root_lookups(started, source), started
    _assert_git_failure_recorded(output, source, said)


def _assert_git_failure_recorded(output: Path, source: Path, said: str) -> None:
    """The refused start is git failing to answer, which a scan records as it records
    any directory git gives no root for: the absolute path."""
    assert _recorded_scan_source(output) == source.as_posix(), said


@pytest.mark.parametrize("variable", ["GIT_DIR", "GIT_WORK_TREE"])
def test_a_variable_naming_a_repository_still_asks_git_for_the_root(tmp_path, variable):
    source = _plain_tree(tmp_path / "plain")
    _outside_every_repository(source)
    elsewhere = tmp_path / "elsewhere" / ".git"

    code, said, output, started = _scan(
        tmp_path, source, extra_env={variable: str(elsewhere)}
    )

    assert code == 2, said
    assert _root_lookups(started, source), started
    _assert_git_failure_recorded(output, source, said)


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory modes")
def test_a_git_entry_in_a_parent_that_cannot_be_listed_still_asks_git(tmp_path):
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root lists a directory whatever its mode")
    top = tmp_path / "unlisted"
    (top / ".git").mkdir(parents=True)
    source = _plain_tree(top / "api")
    # Search but no read: the .git entry can be looked up, not listed.
    top.chmod(0o311)
    try:
        code, said, output, started = _scan(tmp_path, source)
    finally:
        top.chmod(0o755)

    assert code == 2, said
    assert _root_lookups(started, source), started
    _assert_git_failure_recorded(output, source, said)


def test_a_parent_whose_git_entry_cannot_be_checked_still_asks_git(tmp_path):
    top = tmp_path / "unchecked"
    source = _plain_tree(top / "api")
    _outside_every_repository(source)

    code, said, output, started = _scan(tmp_path, source, deny=top.resolve() / ".git")

    assert code == 2, said
    assert _root_lookups(started, source), started
    _assert_git_failure_recorded(output, source, said)
