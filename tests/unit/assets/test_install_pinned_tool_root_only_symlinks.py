# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--assert-root-only`` follows a path the way the kernel does.

``root_only_problems`` used to judge every component of the lexical path by its own
``lstat`` mode and never followed a link. That failed in three ways:

* A symlink's own mode is always 0777 on Linux and the kernel ignores it, so a
  root-owned symlinked ancestor (``/lib`` on a merged-usr system) was reported as
  writable by group and others, and the directories the link leads through were
  never examined.
* ``os.path.abspath`` collapsed ``..`` in the text of the path, so after a symlink
  the check read a different directory from the one the kernel resolves.
* ``os.walk`` ignored errors, so a directory under the target that could not be
  read passed without its contents being examined.

The tests trust the uid that owns their ``tmp_path`` and count only the problems that
name ``tmp_path`` or a path below it, as the tests in test_install_pinned_tool.py do.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX ownership and modes"),
]

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "automated_security_helper" / "assets" / "install-pinned-tool.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("_install_pinned_tool_roots", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = _load_script()


@pytest.fixture(autouse=True)
def _plain_umask():
    """Directories a test makes are 0755, whatever umask the runner has."""
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


def _problems(path: Path, tmp_path: Path) -> "list[str]":
    owner = os.stat(tmp_path).st_uid
    kept = []
    for problem in installer.root_only_problems([path], (owner,)):
        named = Path(problem.split(": ", 1)[0])
        if named == tmp_path or tmp_path in named.parents:
            kept.append(problem)
    return kept


def _tree(parent: Path) -> Path:
    """parent/rules/a.guard with the modes a root-only install leaves."""
    rules = parent / "rules"
    rules.mkdir(parents=True)
    (rules / "a.guard").write_text("rule a { }\n")
    parent.chmod(0o755)
    rules.chmod(0o755)
    (rules / "a.guard").chmod(0o644)
    return rules


def _link(link: Path, target: Path) -> None:
    link.symlink_to(target, target_is_directory=target.is_dir())
    if not os.lstat(link).st_mode & 0o022:
        pytest.skip("a symlink here has a mode that lets no one else write it")


class TestASymlinkOnTheWay:
    def test_a_symlinked_ancestor_is_not_judged_by_its_own_mode(self, tmp_path):
        real = tmp_path / "real"
        _tree(real / "shared")
        link = tmp_path / "link"
        _link(link, real)

        assert _problems(link / "shared" / "rules", tmp_path) == []

    def test_the_directories_a_symlink_leads_through_are_checked(self, tmp_path):
        open_dir = tmp_path / "open"
        _tree(open_dir)
        open_dir.chmod(0o777)
        link = tmp_path / "link"
        _link(link, open_dir)

        try:
            problems = _problems(link / "rules", tmp_path)
        finally:
            open_dir.chmod(0o755)

        assert any(
            p.startswith(f"{open_dir}:") and "write it" in p for p in problems
        ), problems

    def test_dotdot_after_a_symlink_follows_the_link(self, tmp_path):
        """Component by component: ``a/L/..`` is the parent of L's target, not ``a``."""
        elsewhere = tmp_path / "elsewhere"
        _tree(elsewhere / "inner")
        (elsewhere / "d").mkdir()
        (elsewhere / "d").chmod(0o755)
        lexical = tmp_path / "a"
        lexical.mkdir()
        (lexical / "d").mkdir()
        (lexical / "d").chmod(0o777)
        _link(lexical / "L", elsewhere / "inner")

        try:
            problems = _problems(lexical / "L" / ".." / "d", tmp_path)
        finally:
            (lexical / "d").chmod(0o755)

        assert not any(p.startswith(f"{lexical / 'd'}:") for p in problems), (
            "the directory the text of the path names was checked, not the one "
            "the kernel resolves"
        )
        assert problems == []

    def test_a_symlinked_target_is_followed_to_the_real_tree(self, tmp_path):
        real = _tree(tmp_path / "real")
        (real / "a.guard").chmod(0o666)
        link = tmp_path / "link"
        _link(link, real)

        problems = _problems(link, tmp_path)

        assert any(
            p.startswith(f"{real / 'a.guard'}:") and "write it" in p for p in problems
        ), problems

    def test_a_link_owned_by_nobody_trusted_is_still_a_problem(self, tmp_path):
        """A link's mode is skipped, its owner is not."""
        real = tmp_path / "real"
        _tree(real / "shared")
        link = tmp_path / "link"
        _link(link, real)
        owner = os.stat(tmp_path).st_uid

        problems = [
            p
            for p in installer.root_only_problems(
                [link / "shared" / "rules"], (owner + 1,)
            )
            if p.startswith(f"{link}:")
        ]

        assert problems == [f"{link}: owned by uid {owner}"]

    def test_a_loop_of_links_is_a_problem_and_not_a_hang(self, tmp_path):
        first, second = tmp_path / "first", tmp_path / "second"
        first.symlink_to(second)
        second.symlink_to(first)

        problems = installer.root_only_problems([first / "x"], (os.getuid(),))

        assert any("too many levels of symlinks" in p for p in problems), problems


class TestASymlinkInsideTheTree:
    def test_it_is_refused_for_what_it_is(self, tmp_path):
        rules = _tree(tmp_path / "shared")
        _link(rules / "b.guard", rules / "a.guard")

        problems = _problems(rules, tmp_path)

        link = f"{rules / 'b.guard'}:"
        assert any(p.startswith(link) and "is a symlink" in p for p in problems), (
            problems
        )
        assert not any(
            p.startswith(link) and "lets group or others" in p for p in problems
        )


class TestAnUnreadableDirectoryUnderTheTarget:
    def test_it_is_a_problem_not_a_pass(self, tmp_path, monkeypatch):
        rules = _tree(tmp_path / "shared")
        locked = str(rules / "locked")

        def walk(top, topdown=True, onerror=None, followlinks=False):
            # What os.walk does for a directory it cannot list: call onerror, yield
            # nothing. Raised here, not provoked with a mode, so root sees it too.
            if onerror is not None:
                onerror(PermissionError(13, "Permission denied", locked))
            return iter(())

        monkeypatch.setattr(installer.os, "walk", walk)

        problems = _problems(rules, tmp_path)

        assert any(
            p.startswith(f"{locked}:") and "Permission denied" in p for p in problems
        ), problems
