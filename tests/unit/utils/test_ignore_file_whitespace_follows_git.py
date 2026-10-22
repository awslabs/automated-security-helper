# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An ignore-file line's whitespace is read the way git reads it.

git keeps a pattern's leading whitespace, drops only the trailing spaces that a
backslash does not escape, and keeps a trailing tab (``trim_trailing_spaces`` in
git's dir.c). Were ASH to strip every line on both sides before igittigitt parses
it, ``trail.py\\ `` would lose its escaped space and ignore ``trail.py`` instead
of ``trail.py ``. igittigitt 2.2.3 strips leading whitespace itself, and the
whitespace around every escaped space, so `` lead.py`` would ignore ``lead.py``
and ``tab.py<TAB>`` would ignore ``tab.py`` even with the line passed as written.
The expectations below are what ``git check-ignore`` (2.50.1) answered for the
same lines and names.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.get_scan_set import scan_set

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows does not allow a tab, or a trailing space, in a file name",
)

RULES = [" lead.py", "trail.py\\ ", "trail2.py  ", "tab.py\t", "a\\ b.py"]
#: What git ignores for RULES, among NAMES.
IGNORED = {" lead.py", "trail.py ", "trail2.py", "tab.py\t", "a b.py"}
NAMES = [
    " lead.py",
    "lead.py",
    "trail.py ",
    "trail.py",
    "trail2.py",
    "trail2.py ",
    "tab.py",
    "tab.py\t",
    "a b.py",
    "ab.py",
]


def _tree(tmp_path: Path, rules: list[str], names: list[str]) -> Path:
    source = tmp_path / "src"
    source.mkdir()
    (source / ".gitignore").write_text("\n".join(rules) + "\n", encoding="utf-8")
    for name in names:
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x = 1\n", encoding="utf-8")
    return source


def _scanned(source: Path, tmp_path: Path) -> set[str]:
    found = scan_set(source=str(source), output=str(tmp_path / "out"))
    return {os.path.relpath(name, source) for name in found}


def test_each_line_ignores_what_git_ignores(tmp_path):
    source = _tree(tmp_path, RULES, NAMES)

    scanned = _scanned(source, tmp_path)

    assert {name for name in NAMES if name not in scanned} == IGNORED


def test_a_leading_space_does_not_prune_the_directory_without_one(tmp_path):
    """The walk prunes directories with the root .gitignore before the full spec
    runs, so a rule keeps its leading space and prunes only the directory whose
    name has one."""
    source = _tree(tmp_path, [" dir/"], ["dir/x.py", " dir/y.py"])

    scanned = _scanned(source, tmp_path)

    assert "dir/x.py" in scanned
    assert " dir/y.py" not in scanned


def test_a_comment_needs_its_hash_in_the_first_column(tmp_path):
    """git reads " #x.py" as a pattern for the file " #x.py", and "#x.py" as a
    comment."""
    source = _tree(tmp_path, ["#x.py", " #y.py"], ["#x.py", " #y.py"])

    scanned = _scanned(source, tmp_path)

    assert "#x.py" in scanned
    assert " #y.py" not in scanned


#: git splits an ignore file on LF alone and drops one CR before each LF; a
#: CR anywhere else is part of the pattern. "cr<CR><CR><LF>" loses exactly
#: one CR, so it ignores "cr<CR>" and not "cr".
CR_RULES = b"a\rb.py\nx.py\r\ncr\r\r\ny.py\r"
CR_NAMES = ["a", "b.py", "a\rb.py", "x.py", "y.py", "keep.py", "cr", "cr\r"]
CR_IGNORED = {"a\rb.py", "x.py", "y.py", "cr\r"}


def _bytes_tree(tmp_path: Path, ignore_files: dict, names: list[str]) -> Path:
    source = tmp_path / "src"
    source.mkdir()
    for relative, data in ignore_files.items():
        (source / relative).parent.mkdir(parents=True, exist_ok=True)
        (source / relative).write_bytes(data)
    for name in names:
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x = 1\n", encoding="utf-8")
    return source


def test_a_carriage_return_inside_a_line_is_part_of_the_pattern(tmp_path):
    source = _bytes_tree(tmp_path, {".gitignore": CR_RULES}, CR_NAMES)

    scanned = _scanned(source, tmp_path)

    assert {name for name in CR_NAMES if name not in scanned} == CR_IGNORED


def test_a_carriage_return_does_not_prune_a_directory_the_rule_does_not_name(
    tmp_path,
):
    source = _bytes_tree(tmp_path, {".gitignore": b"a\rb.py\n"}, ["a/z.py"])

    assert "a/z.py" in _scanned(source, tmp_path)


def test_a_nested_ignore_file_splits_on_line_feeds_alone(tmp_path):
    names = ["sub/c", "sub/d.py", "sub/c\rd.py"]
    source = _bytes_tree(tmp_path, {"sub/.gitignore": b"c\rd.py\r\n"}, names)

    scanned = _scanned(source, tmp_path)

    assert {name for name in names if name not in scanned} == {"sub/c\rd.py"}


def test_an_ignore_file_the_caller_names_splits_on_line_feeds_alone(tmp_path):
    names = ["e", "f.py", "e\rf.py"]
    source = _bytes_tree(tmp_path, {".myignore": b"e\rf.py\n"}, names)

    found = scan_set(
        source=str(source), output=str(tmp_path / "out"), ignorefile=[".myignore"]
    )
    scanned = {os.path.relpath(name, source) for name in found}

    assert {name for name in names if name not in scanned} == {"e\rf.py"}


#: git skips a UTF-8 byte order mark before an ignore file's first pattern
#: (skip_utf8_bom in dir.c): a root file whose first line is a directory
#: pattern, and a nested one. Only that one: a mark at the start of a later
#: line, or a second mark after the first, is part of its pattern, which then
#: matches no file.
BOM = b"\xef\xbb\xbf"
BOM_FILES = {
    ".gitignore": BOM + b"bomdir/\nother.py\n",
    "sub/.gitignore": BOM + b"nested.py\n",
    "mid/.gitignore": b"first.py\n" + BOM + b"second.py\n",
    "two/.gitignore": BOM + BOM + b"twice.py\n",
}
BOM_NAMES = [
    "bomdir/x.py",
    "other.py",
    "sub/nested.py",
    "keep.py",
    "sub/keep.py",
    "mid/first.py",
    "mid/second.py",
    "two/twice.py",
]
BOM_IGNORED = {"bomdir/x.py", "other.py", "sub/nested.py", "mid/first.py"}


def test_a_byte_order_mark_is_not_part_of_the_first_pattern(tmp_path):
    source = _bytes_tree(tmp_path, BOM_FILES, BOM_NAMES)

    scanned = _scanned(source, tmp_path)

    assert {name for name in BOM_NAMES if name not in scanned} == BOM_IGNORED


def test_a_byte_order_mark_in_an_ignore_file_the_caller_names_is_skipped(tmp_path):
    names = ["named.py", "keep.py"]
    source = _bytes_tree(tmp_path, {".myignore": BOM + b"named.py\n"}, names)

    found = scan_set(
        source=str(source), output=str(tmp_path / "out"), ignorefile=[".myignore"]
    )
    scanned = {os.path.relpath(name, source) for name in found}

    assert {name for name in names if name not in scanned} == {"named.py"}


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_the_byte_order_mark_expectations_are_gits(tmp_path):
    repo = _bytes_tree(tmp_path, BOM_FILES, BOM_NAMES)
    env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    subprocess.run(["git", "init", "-q"], cwd=repo, env=env, check=True)

    ignored = {
        name
        for name in BOM_NAMES
        if subprocess.run(
            ["git", "check-ignore", "-q", "--", name], cwd=repo, env=env
        ).returncode
        == 0
    }

    assert ignored == BOM_IGNORED


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_the_carriage_return_expectations_are_gits(tmp_path):
    repo = _bytes_tree(tmp_path, {".gitignore": CR_RULES}, CR_NAMES)
    env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    subprocess.run(["git", "init", "-q"], cwd=repo, env=env, check=True)

    ignored = {
        name
        for name in CR_NAMES
        if subprocess.run(
            ["git", "check-ignore", "-q", "--", name], cwd=repo, env=env
        ).returncode
        == 0
    }

    assert ignored == CR_IGNORED


#: A "!" re-includes a file only when no directory above it is excluded, as git
#: reads it (a negation cannot reach below an excluded directory). "vendor/*"
#: excludes vendor's children but not vendor, so "!vendor/keep.js" brings
#: keep.js back; "lib/" excludes lib itself, so "!lib/keep.js" does not. The
#: same in a nested ignore file, whose patterns are relative to its directory.
NEGATION_FILES = {
    ".gitignore": b"vendor/*\n!vendor/keep.js\nlib/\n!lib/keep.js\n",
    "sub/.gitignore": b"deps/*\n!deps/keep.js\npkg/\n!pkg/keep.js\n",
}
NEGATION_NAMES = [
    "vendor/a.js",
    "vendor/keep.js",
    "lib/a.js",
    "lib/keep.js",
    "sub/deps/a.js",
    "sub/deps/keep.js",
    "sub/pkg/a.js",
    "sub/pkg/keep.js",
    "keep.py",
]
NEGATION_IGNORED = {
    "vendor/a.js",
    "lib/a.js",
    "lib/keep.js",
    "sub/deps/a.js",
    "sub/pkg/a.js",
    "sub/pkg/keep.js",
}


def test_a_negation_brings_back_what_git_brings_back(tmp_path):
    source = _bytes_tree(tmp_path, NEGATION_FILES, NEGATION_NAMES)

    scanned = _scanned(source, tmp_path)

    assert {name for name in NEGATION_NAMES if name not in scanned} == (
        NEGATION_IGNORED
    )


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_the_negation_expectations_are_gits(tmp_path):
    repo = _bytes_tree(tmp_path, NEGATION_FILES, NEGATION_NAMES)
    env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    subprocess.run(["git", "init", "-q"], cwd=repo, env=env, check=True)

    ignored = {
        name
        for name in NEGATION_NAMES
        if subprocess.run(
            ["git", "check-ignore", "-q", "--", name], cwd=repo, env=env
        ).returncode
        == 0
    }

    assert ignored == NEGATION_IGNORED


#: git reads an ignore file as bytes, so a line that is not UTF-8 is a pattern like
#: any other, matching the file whose name holds the same bytes. ASH decoded it
#: strictly, and UnicodeDecodeError came out of scan_set. Read with
#: surrogateescape, the bytes come back as the str os.walk gives such a name.
NON_UTF8_FILES = {
    ".gitignore": b"caf\xe9.py\nd\xe9j\xe0/\n",
    "sub/.gitignore": b"na\xefve.py\n",
}
NON_UTF8_NAMES = [
    os.fsdecode(name)
    for name in (
        b"caf\xe9.py",
        b"cafe.py",
        b"d\xe9j\xe0/x.py",
        b"sub/na\xefve.py",
        b"sub/naive.py",
        b"keep.py",
    )
]
NON_UTF8_IGNORED = {b"caf\xe9.py", b"d\xe9j\xe0/x.py", b"sub/na\xefve.py"}


def _non_utf8_tree(tmp_path: Path) -> Path:
    try:
        return _bytes_tree(tmp_path, NON_UTF8_FILES, NON_UTF8_NAMES)
    except OSError as error:
        pytest.skip(f"this filesystem cannot hold a name that is not UTF-8: {error}")


def test_a_line_that_is_not_utf8_is_a_pattern_as_in_git(tmp_path):
    source = _non_utf8_tree(tmp_path)

    scanned = _scanned(source, tmp_path)

    # As bytes: a failure report holding a lone surrogate cannot leave a worker.
    assert {
        os.fsencode(name) for name in NON_UTF8_NAMES if name not in scanned
    } == NON_UTF8_IGNORED


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_the_expectations_for_lines_that_are_not_utf8_are_gits(tmp_path):
    repo = _non_utf8_tree(tmp_path)
    env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    subprocess.run(["git", "init", "-q"], cwd=repo, env=env, check=True)

    ignored = {
        os.fsencode(name)
        for name in NON_UTF8_NAMES
        if subprocess.run(
            ["git", "check-ignore", "-q", "--", name], cwd=repo, env=env
        ).returncode
        == 0
    }

    assert ignored == NON_UTF8_IGNORED


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_the_expectations_are_gits(tmp_path):
    """Pins IGNORED to what git itself answers, so the table cannot drift."""
    repo = _tree(tmp_path, RULES, NAMES)
    env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    subprocess.run(["git", "init", "-q"], cwd=repo, env=env, check=True)

    ignored = {
        name
        for name in NAMES
        if subprocess.run(
            ["git", "check-ignore", "-q", "--", name], cwd=repo, env=env
        ).returncode
        == 0
    }

    assert ignored == IGNORED
