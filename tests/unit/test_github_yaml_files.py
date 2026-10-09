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
is planted under tests/pytest-temp, and scanning it (``os.scandir`` or
``os.listdir``) is made to raise FileNotFoundError, which is what a teardown between
listing and descending looks like to the walker. Whether a walker then raises depends
on the interpreter: measured on py3.10 to py3.14, 3.10's and 3.11's pathlib propagate
it and 3.12 to 3.14's glob swallows it. So the property checked is the
version-independent one underneath: the enumerations now used never try to enter
the planted directory, and the old ``**`` walk does, under the same simulation, or
the simulation proves nothing.

The control runs that old walk over a private tree under ``tmp_path`` with its own
tests/pytest-temp, never over the live repository. Over the live one it raced the
real scratch tree like the walk it reproduces: with directories churning beside it,
the ``**`` glob aborted early on 3.10 and 3.11 before it reached the planted
directory, and the control failed about half the time.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
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
_YAML = re.compile(r"\.ya?ml$")
_USES_CHECKOUT = re.compile(
    r"^\s*(?:-\s*)?uses:\s*['\"]?actions/checkout@", re.MULTILINE
)


# Directories made to vanish, each with the scans attempted inside it. The audit hook
# below cannot be removed once added, so it is installed once per process and does
# nothing while this is empty.
_VANISHING: list[tuple[Path, list[str]]] = []
_HOOK_INSTALLED = False


_SCAN_EVENTS = frozenset({"os.scandir", "os.listdir"})


def _vanish_on_scan(event: str, args: tuple) -> None:
    """Make scanning a vanishing directory fail as a teardown would.

    An audit hook rather than a patched ``os.scandir``: pathlib's glob holds its own
    reference to the C function on some interpreters (3.10, 3.13), which a module
    patch never reaches, while every call raises its audit event. ``os.listdir``
    too, because ``Path.iterdir()`` uses it on 3.10 to 3.12.
    """
    if not _VANISHING or event not in _SCAN_EVENTS or not args:
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


@contextmanager
def _vanishing(directory: Path) -> Iterator[list[str]]:
    """While open, scanning ``directory`` or anything under it fails.

    Yields the list of paths a walker tried to scan there.
    """
    global _HOOK_INSTALLED
    if not _HOOK_INSTALLED:
        sys.addaudithook(_vanish_on_scan)
        _HOOK_INSTALLED = True
    entry: tuple[Path, list[str]] = (directory.resolve(), [])
    _VANISHING.append(entry)
    try:
        yield entry[1]
    finally:
        _VANISHING.remove(entry)


def _plant(scratch_root: Path) -> Path:
    """A directory under ``scratch_root`` holding a workflow and a test source."""
    planted = scratch_root / f"vanishing-{uuid.uuid4().hex}"
    workflows = planted / "nested" / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "planted.yml").write_text("on: push\n", encoding="utf-8")
    (planted / "planted_probe.py").write_text("x = 1\n", encoding="utf-8")
    return planted


@pytest.fixture
def vanishing_scratch_dir():
    """A directory under the real tests/pytest-temp that vanishes when entered."""
    planted = _plant(ASH_TEST_TEMP_ROOT)
    try:
        with _vanishing(planted) as entered:
            yield planted, entered
    finally:
        shutil.rmtree(planted, ignore_errors=True)


def old_walk_enters_the_scratch_tree(private_root: Path) -> bool:
    """Run the old ``**`` walk over a private tree; did it try to enter scratch?

    The tree has the repository's shape where it matters: a .github/workflows and a
    tests/pytest-temp holding the planted directory. Nothing else writes to it, so
    the result does not depend on what other workers are doing.
    """
    (private_root / ".github" / "workflows").mkdir(parents=True)
    (private_root / ".github" / "workflows" / "ci.yml").write_text(
        "on: push\n", encoding="utf-8"
    )
    planted = _plant(private_root / "tests" / "pytest-temp")
    with _vanishing(planted) as entered:
        try:
            list(private_root.glob("**/.github/workflows/*.yml"))
        except FileNotFoundError:
            pass  # 3.10 and 3.11 propagate it: the failure the Windows leg reported.
    return bool(entered)


def test_the_simulation_reproduces_the_race(tmp_path):
    """Control: the `**` walk the guard tests used to do tries to enter it."""
    assert old_walk_enters_the_scratch_tree(tmp_path / "repo"), (
        "the old walk never reached the planted directory, so the simulation "
        "proves nothing about the enumerations below"
    )


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


def _tracked_files() -> list[str]:
    """Tracked paths, or a failure that says why they could not be listed."""
    try:
        listed = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=REPO_ROOT,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError:
        pytest.fail("git is not installed; this check reads the tracked file list")
    if listed.returncode != 0:
        pytest.fail(
            f"git ls-files exited {listed.returncode}: "
            f"{listed.stderr.decode(errors='replace')}"
        )
    tracked = [name for name in listed.stdout.decode("utf-8").split("\0") if name]
    assert tracked, "git ls-files listed nothing, so this would compare nothing"
    return tracked


def test_the_ci_yaml_enumeration_is_complete():
    """Every tracked workflow and composite action, so a new .github root is noticed."""
    tracked = {name for name in _tracked_files() if _TRACKED.search(name)}
    assert tracked, "no tracked workflow or composite action matched"
    found = {
        path.relative_to(REPO_ROOT).as_posix() for path in github_yaml_files(REPO_ROOT)
    }
    assert found == tracked, (
        f"missing: {sorted(tracked - found)}; untracked extras: {sorted(found - tracked)}. "
        f"Add a new .github root to GITHUB_YAML_ROOTS ({GITHUB_YAML_ROOTS})."
    )


def test_every_tracked_yaml_that_checks_out_is_enumerated():
    """A checkout in any YAML, wherever it sits, is in the enumerated set.

    The pattern above cannot see a composite action at
    ``actions/<group>/<name>/action.yml`` or an ``action.yml`` outside ``.github``.
    Anything that runs ``actions/checkout`` is a workflow or action the two guard
    tests have to read, so its absence from github_yaml_files() fails here.
    """
    found = {
        path.relative_to(REPO_ROOT).as_posix() for path in github_yaml_files(REPO_ROOT)
    }
    checking_out = sorted(
        name
        for name in _tracked_files()
        if _YAML.search(name)
        and (REPO_ROOT / name).is_file()
        and _USES_CHECKOUT.search(
            (REPO_ROOT / name).read_text(encoding="utf-8", errors="replace")
        )
    )
    assert checking_out, "no tracked YAML uses actions/checkout, so this checks nothing"
    missing = [name for name in checking_out if name not in found]
    assert missing == [], (
        f"these tracked YAML files run actions/checkout but github_yaml_files() does "
        f"not list them, so the persist-credentials and canonical-CLI guards never "
        f"read them: {missing}"
    )


def test_the_checkout_pattern_matches_the_shapes_in_use():
    for line in (
        "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "        uses: actions/checkout@v4",
        "    - uses: 'actions/checkout@v4'",
    ):
        assert _USES_CHECKOUT.search(line), line
    assert not _USES_CHECKOUT.search("# uses: actions/checkout@v4")
