# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Enumerations of CI YAML and test sources never descend into the scratch tree.

Why this exists
---------------
test_checkout_persist_credentials raised FileNotFoundError [WinError 3] on a
windows-latest py3.11 leg, from under tests\\pytest-temp\\: it found workflows with
``REPO.glob("**/.github/workflows/*.yml")``, and that walk descended into a directory
another xdist worker's ``ash_temp_path`` teardown removed between listing it and
entering it. test_ci_runs_the_canonical_cli had the same walk, and
test_tests_restore_global_modules walked tests/ with ``rglob``.

The race cannot be timed in a test, so it is simulated where it happens: a directory
is planted under tests/pytest-temp, and ``os.scandir`` is made to raise
FileNotFoundError for it, which is what a teardown between listing and descending
looks like to the walker. Whether a walker then raises depends on the interpreter:
measured on py3.10 to py3.14, only 3.11's pathlib propagated it; the others' glob
swallows it. So the property checked is the version-independent one underneath:
the enumerations now used never try to enter the planted directory, and the old
``**`` walk does, under the same simulation, or the simulation proves nothing.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from tests.unit import test_checkout_persist_credentials as persist_credentials
from tests.unit import test_ci_runs_the_canonical_cli as canonical_cli
from tests.unit import test_tests_restore_global_modules as restore_globals
from tests.utils.helpers import (
    ASH_TEST_TEMP_ROOT,
    GITHUB_YAML_ROOTS,
    github_yaml_files,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

_TRACKED = re.compile(
    r"(?:^|/)\.github/(?:workflows/[^/]+\.ya?ml|actions/[^/]+/action\.ya?ml)$"
)


# Directories made to vanish, each with the scans attempted inside it. The audit hook
# below cannot be removed once added, so it is installed once per process and does
# nothing while this is empty.
_VANISHING: list[tuple[Path, list[str]]] = []
_HOOK_INSTALLED = False


def _vanish_on_scan(event: str, args: tuple) -> None:
    """Make ``os.scandir`` of a vanishing directory fail as a teardown would.

    An audit hook rather than a patched ``os.scandir``: pathlib's glob holds its own
    reference to the C function on some interpreters (3.10, 3.13), which a module
    patch never reaches, while every call to it raises the ``os.scandir`` audit event.
    """
    if not _VANISHING or event != "os.scandir" or not args:
        return
    target = args[0]
    if isinstance(target, int):
        return
    try:
        resolved = Path(os.fsdecode(target)).resolve()
    except (OSError, TypeError, ValueError):
        return
    for vanished, entered in _VANISHING:
        if resolved.is_relative_to(vanished):
            entered.append(str(resolved))
            raise FileNotFoundError(2, "No such file or directory", str(resolved))


@pytest.fixture
def vanishing_scratch_dir():
    """A directory under tests/pytest-temp that is gone by the time a walk enters it.

    Yields the directory and the list of paths a walker tried to scan inside it.
    """
    global _HOOK_INSTALLED
    if not _HOOK_INSTALLED:
        sys.addaudithook(_vanish_on_scan)
        _HOOK_INSTALLED = True
    planted = ASH_TEST_TEMP_ROOT / f"vanishing-{uuid.uuid4().hex}"
    workflows = planted / "nested" / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "planted.yml").write_text("on: push\n", encoding="utf-8")
    (planted / "planted_probe.py").write_text("x = 1\n", encoding="utf-8")
    entry = (planted.resolve(), [])
    _VANISHING.append(entry)
    try:
        yield planted, entry[1]
    finally:
        _VANISHING.remove(entry)
        shutil.rmtree(planted, ignore_errors=True)


def test_the_simulation_reproduces_the_race(vanishing_scratch_dir):
    """Control: the `**` walk the guard tests used to do tries to enter it."""
    _planted, entered = vanishing_scratch_dir
    try:
        list(REPO_ROOT.glob("**/.github/workflows/*.yml"))
    except FileNotFoundError:
        pass  # What 3.11 does: the failure the windows-latest leg reported.
    assert entered, "the old walk never reached the planted directory"


def test_the_ci_yaml_enumeration_does_not_walk_into_the_scratch_tree(
    vanishing_scratch_dir,
):
    planted, entered = vanishing_scratch_dir
    files = github_yaml_files(REPO_ROOT)
    assert files, "the enumeration found no workflows at all"
    assert entered == []
    assert not any(path.resolve().is_relative_to(planted.resolve()) for path in files)


@pytest.mark.parametrize(
    "enumerate_files",
    [persist_credentials._files, canonical_cli._files],
    ids=["test_checkout_persist_credentials", "test_ci_runs_the_canonical_cli"],
)
def test_the_guard_tests_enumerations_do_not_walk_into_the_scratch_tree(
    vanishing_scratch_dir, enumerate_files
):
    """The two tests that raised, through their own enumeration functions."""
    planted, entered = vanishing_scratch_dir
    files = enumerate_files()
    assert files
    assert entered == []
    assert not any(path.resolve().is_relative_to(planted.resolve()) for path in files)


def test_the_test_source_enumeration_does_not_walk_into_the_scratch_tree(
    vanishing_scratch_dir,
):
    planted, entered = vanishing_scratch_dir
    files = restore_globals._test_files()
    assert Path(restore_globals.__file__).resolve() in {p.resolve() for p in files}
    assert entered == []
    assert not any(path.resolve().is_relative_to(planted.resolve()) for path in files)


def test_the_ci_yaml_enumeration_is_complete():
    """Every tracked workflow and composite action, so a new .github root is noticed."""
    if shutil.which("git") is None:
        pytest.skip("git is not installed, so the tracked set cannot be listed")
    listed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
    )
    if listed.returncode != 0:
        pytest.skip(f"not a git work tree: {listed.stderr.decode(errors='replace')}")
    tracked = {
        name
        for name in listed.stdout.decode("utf-8").split("\0")
        if name and _TRACKED.search(name)
    }
    found = {
        path.relative_to(REPO_ROOT).as_posix() for path in github_yaml_files(REPO_ROOT)
    }
    assert found == tracked, (
        f"missing: {sorted(tracked - found)}; untracked extras: {sorted(found - tracked)}. "
        f"Add a new .github root to GITHUB_YAML_ROOTS ({GITHUB_YAML_ROOTS})."
    )
