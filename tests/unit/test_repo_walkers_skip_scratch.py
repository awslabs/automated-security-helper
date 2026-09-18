# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No test may walk the repository root with ``rglob``.

Why this file exists
--------------------
``tests/pytest-temp/<uuid>/`` is the tests' own scratch area, inside the
repository and gitignored, and the ``ash_temp_path`` fixture ``shutil.rmtree``s a
subtree of it on teardown. Under ``-n auto`` that teardown runs while other
workers are mid-walk, so any test that walks the repository root races it.

There are two distinct races, and that distinction is why this is a guard rather
than a third individual fix:

1. **Read after enumerate.** ``sorted(root.rglob("*.py"))`` is materialised in
   full, then each file is read. A file listed at the start can be gone by the
   time it is read. Fixed once, in ``test_project_isolation.py``, by filtering the
   walk's output.
2. **Scandir during descent.** ``rglob`` raises from *inside* its own traversal,
   before it yields anything, when a directory it listed is removed before it
   descends into it. Measured on macos-14 py3.11, in a different walker::

       _candidate_files -> REPO_ROOT.rglob("*")
         pathlib.py:397 _iterate_directories   (recursive)
         pathlib.py:386   with scandir(parent_path) as scandir_it:
         -> os.scandir(self)
         FileNotFoundError: .../tests/pytest-temp/<uuid>/test_output_dir

   No filter on the output can prevent that, because there is no output.

   Seen on one leg of a run whose other legs passed. Whether that is a pathlib
   version difference or simply which worker lost the race is **not** established:
   an attempt to reproduce the raise synthetically on 3.11 and 3.13 failed to hit
   the window on either. So the leg it appeared on is a sample, not the affected
   set, and the fix is not scoped to an interpreter.

Fixing (1) does not fix (2). That is not a hypothetical: the first fix landed and
a second walker failed the same way three hours later, on a leg that had just been
added to the matrix. So the rule is structural -- walk with
``tests.utils.helpers.iter_repo_files``, which prunes ``dirnames`` in place so
``os.walk`` never descends into the scratch tree. Pruning removes the race;
filtering and exception-catching only narrow it.

Why this is an AST check and not a grep
---------------------------------------
A regex over source lines flags the traceback quoted above, which lives in a
docstring in ``helpers.py``. The cheapest way to make a text-matching guard green
is then to delete the explanation, which is precisely backwards -- the same
failure ``test_prose_about_the_hazard_is_not_counted_as_the_hazard`` documents in
``test_project_isolation.py``. Matching ``ast.Call`` nodes makes prose invisible
by construction, so the explanation can stay.

What this proves, and what it does not
--------------------------------------
It finds ``REPO_ROOT.glob(...)`` and ``REPO_ROOT.rglob(...)`` by AST, under the
names this repository actually uses for its root. A walker that binds the root to
some other name and calls ``rglob`` on it would pass this and still race; the
mitigation is that ``iter_repo_files`` is now the obvious thing to reach for, not
that this sweep is exhaustive.

It deliberately does not forbid ``rglob`` on a subdirectory. Walking
``automated_security_helper/`` is safe -- the scratch tree is not under it, so
there is nothing to race.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests.utils.helpers import (
    ASH_TEST_TEMP_ROOT,
    is_under_test_scratch,
    iter_repo_files,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = REPO_ROOT / "tests"

#: Names this repository binds the repository root to.
_ROOT_NAMES = frozenset({"REPO_ROOT", "repo_root"})
_WALK_METHODS = frozenset({"glob", "rglob"})

#: (file name, enclosing function) pairs exempted, each with a reason. Keyed by
#: function rather than by file so converting one walker in a file does not
#: silently exempt the next one added to it.
_ALLOWED = {
    (
        "test_agent_plugin_ash_version.py",
        "test_every_version_files_path_exists",
    ): (
        "Globs commitizen's version_files entries, which are literal paths with "
        "no wildcard, so the glob resolves one path and never descends. "
        "test_the_version_files_exemption_is_still_sound asserts that."
    ),
}


def _root_walk_calls(source: str) -> list[tuple[int, str]]:
    """``(lineno, enclosing function)`` for every root-walking call in ``source``."""
    tree = ast.parse(source)
    enclosing: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(node):
                if hasattr(child, "lineno"):
                    enclosing.setdefault(child.lineno, node.name)

    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr not in _WALK_METHODS:
            continue
        if not isinstance(func.value, ast.Name) or func.value.id not in _ROOT_NAMES:
            continue
        found.append((node.lineno, enclosing.get(node.lineno, "<module>")))
    return found


def _test_sources():
    for path in iter_repo_files(TESTS_ROOT, skip_dirs=frozenset({"__pycache__"})):
        if path.suffix == ".py":
            yield path


class TestNoTestWalksTheRepoRootWithRglob:
    def test_the_sweep_finds_test_files_at_all(self):
        """Anti-vacuity: an empty walk would make the assertion below pass."""
        sources = list(_test_sources())
        assert len(sources) > 100, (
            f"the sweep found only {len(sources)} test files, so it is not "
            "walking the tests tree and a clean result means nothing"
        )
        names = {path.name for path in sources}
        assert "test_project_isolation.py" in names
        assert "test_agent_plugin_ash_version.py" in names

    def test_the_matcher_recognizes_the_pattern_it_forbids(self):
        """Anti-vacuity: prove the detector fires before trusting that it found none."""
        assert _root_walk_calls("def f():\n    return REPO_ROOT.rglob('*')\n") == [
            (2, "f")
        ]
        assert _root_walk_calls("def g():\n    return list(repo_root.glob(n))\n") == [
            (2, "g")
        ]
        # A subdirectory walk is safe and must not be flagged.
        assert _root_walk_calls("def h():\n    return PKG_ROOT.rglob('*.py')\n") == []
        assert _root_walk_calls("def i():\n    return root.rglob('*.py')\n") == []

    def test_prose_about_the_hazard_is_not_counted_as_the_hazard(self):
        """``helpers.py`` quotes the traceback; an AST check must not see it.

        Stated as a test because a future maintainer hitting a false positive here
        would reasonably reach for the delete key on the explanation, and the
        explanation is the most useful thing in that module.
        """
        helpers = (TESTS_ROOT / "utils" / "helpers.py").read_text(encoding="utf-8")
        assert "REPO_ROOT.rglob" in helpers, (
            "helpers.py no longer quotes the traceback, so this test is checking "
            "nothing about how the detector treats prose"
        )
        assert _root_walk_calls(helpers) == []

    def test_no_test_walks_the_repo_root(self):
        offenders: dict[str, str] = {}
        for path in _test_sources():
            for lineno, function in _root_walk_calls(path.read_text(encoding="utf-8")):
                if (path.name, function) in _ALLOWED:
                    continue
                offenders[f"{path.relative_to(REPO_ROOT)}:{lineno}"] = function

        assert offenders == {}, (
            "these walk the repository root with glob/rglob, which raises "
            "FileNotFoundError from inside its own descent when another xdist "
            "worker's ash_temp_path teardown removes a directory mid-walk. Use "
            "tests.utils.helpers.iter_repo_files, which prunes the scratch tree "
            "during traversal so the descent never happens: " + repr(offenders)
        )

    def test_the_version_files_exemption_is_still_sound(self):
        """The one exemption holds only while no entry carries a wildcard.

        ``REPO_ROOT.glob("a/b.md")`` resolves one path. ``REPO_ROOT.glob("**/b.md")``
        walks the whole tree and would race exactly like the rest. So the exemption
        is conditional, and this is the condition.

        ``tomllib`` is imported here rather than at module scope, and skipped rather
        than depended on, because it is standard library only from 3.11 while
        ``requires-python`` starts at 3.10. A module-level import took out the whole
        file -- and therefore the guard itself -- on every 3.10 leg. The guard is
        the valuable part and must run everywhere; only this one assertion needs a
        TOML parser, so only this one skips.
        """
        tomllib = pytest.importorskip(
            "tomllib",
            reason="stdlib from 3.11; requires-python starts at 3.10",
        )
        with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
            settings = tomllib.load(handle)["tool"]["commitizen"]

        entries = settings["version_files"]
        assert entries, "version_files is empty, so the exemption guards nothing"
        wildcarded = [entry for entry in entries if "*" in entry or "?" in entry]
        assert wildcarded == [], (
            "a version_files entry now carries a wildcard, so "
            "test_every_version_files_path_exists globs recursively and races the "
            "scratch tree. Either drop the wildcard or convert that test to "
            "iter_repo_files and remove its exemption here: " + repr(wildcarded)
        )


class TestIterRepoFilesPrunesTheScratchTree:
    """The helper's own behavior, since five call sites now depend on it."""

    def test_a_scratch_file_is_not_yielded(self, ash_temp_path):
        planted = ash_temp_path / "planted_probe.py"
        planted.write_text("x = 1\n", encoding="utf-8")

        assert planted.exists(), "the fixture did not write the probe"
        yielded = {p.resolve() for p in iter_repo_files(REPO_ROOT)}
        assert planted.resolve() not in yielded

    def test_it_yields_real_source(self):
        """The companion: pruning must not have emptied the walk."""
        yielded = {p.name for p in iter_repo_files(REPO_ROOT)}
        assert "pyproject.toml" in yielded
        assert "helpers.py" in yielded

    def test_prune_scratch_false_does_yield_the_scratch_file(self, ash_temp_path):
        """The opt-out has to opt out, or the control that uses it proves nothing."""
        planted = ash_temp_path / "planted_probe.py"
        planted.write_text("x = 1\n", encoding="utf-8")

        yielded = {p.resolve() for p in iter_repo_files(REPO_ROOT, prune_scratch=False)}
        assert planted.resolve() in yielded

    def test_skip_dirs_is_honored(self):
        yielded = set(iter_repo_files(REPO_ROOT, skip_dirs=frozenset({"tests"})))
        assert not any("tests" in p.relative_to(REPO_ROOT).parts for p in yielded)
        assert yielded, "skipping tests/ emptied the whole walk"

    def test_a_vanishing_path_outside_the_scratch_tree_is_not_silently_skipped(
        self, tmp_path
    ):
        """The tolerance must be narrow, or blindness reads as cleanliness.

        ``os.walk`` ignores errors by default. If ``iter_repo_files`` inherited
        that, a walk that failed for any reason would return a short list and every
        sweep built on it would report a clean repository. Only the scratch tree is
        silently skipped; this pins that a path outside it is not classified as
        scratch, which is what routes it to the re-raising branch.
        """
        outside = tmp_path / "not-scratch"
        outside.mkdir()

        assert not is_under_test_scratch(outside)
        assert is_under_test_scratch(ASH_TEST_TEMP_ROOT / "whatever")

    def test_the_scratch_root_is_inside_the_repository(self):
        """If it were not, pruning it would be a no-op and this is all theatre."""
        assert ASH_TEST_TEMP_ROOT.resolve().is_relative_to(REPO_ROOT.resolve())


class TestTheGuardWouldCatchANewOffender:
    """Prove the exemption list is narrow rather than the detector broken.

    ``test_no_test_walks_the_repo_root`` passes partly because one function is
    exempted. If the detector were broken it would pass for the wrong reason and
    look identical, so assert that the same detector does find the exempted call.
    """

    def test_the_detector_finds_the_exempted_call(self):
        source = (TESTS_ROOT / "unit" / "test_agent_plugin_ash_version.py").read_text(
            encoding="utf-8"
        )
        functions = {function for _, function in _root_walk_calls(source)}

        assert "test_every_version_files_path_exists" in functions, (
            "the detector no longer finds the one call it is supposed to be "
            "exempting, so either that test was converted -- in which case drop "
            "the entry from _ALLOWED -- or the detector is blind"
        )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
