# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A call for other inputs walks its own tree and leaves the run's pair as it is.

``get_scan_set.scan_set`` writes the scan set, the ignore report and a record of
the run, and a later call of the same run reads the pair back only when its
inputs match the record's: the same source and the same ignore files. A call of
the run with other inputs walks its own tree. It does not write: the pair and the
record stay those of the call that wrote them, so the next call with the
writer's inputs still reads them back, and the scan set the run reports
(``scan_set_this_run_wrote``) is always the one the run's writer built.

The ignore files are compared as the walk resolves them: below the source when
relative, with ``.`` segments and repeated separators removed, in no particular
order and once each. ``..`` is never folded, because the system resolves the
component before it.

Every path here is under ``tmp_path``. The walk is counted by wrapping
``_collect_ignorefiles_and_all_files``.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.utils import get_scan_set as gss

RUN = "0123456789abcdef" * 2
LIST_NAME = gss.SCAN_START_FILE_NAMES[1]


@pytest.fixture
def walks(monkeypatch) -> List[str]:
    """The source of each walk ``scan_set`` makes."""
    seen: List[str] = []
    real = gss._collect_ignorefiles_and_all_files

    def counting(path, *args, **kwargs):
        seen.append(os.fspath(path))
        return real(path, *args, **kwargs)

    monkeypatch.setattr(gss, "_collect_ignorefiles_and_all_files", counting)
    return seen


def _tree(root: Path, *names: str) -> Path:
    root.mkdir()
    for name in names:
        (root / name).write_text("x = 1\n", encoding="utf-8")
    return root


def _names(listing: List[str]) -> List[str]:
    return sorted(os.path.basename(entry) for entry in listing)


def _record(output: Path) -> dict:
    return json.loads((output / gss.SCAN_SET_RUN_FILE_NAME).read_text(encoding="utf-8"))


def test_two_callers_alternating_walk_once_for_the_writer_and_each_time_for_the_other(
    tmp_path, walks
):
    """The writer is read back every time; the other caller walks every time."""
    writers_tree = _tree(tmp_path / "a", "only_a.py")
    other_tree = _tree(tmp_path / "b", "only_b.py")
    output = tmp_path / "out"

    seen = []
    for tree in (writers_tree, other_tree, writers_tree, other_tree, writers_tree):
        seen.append(gss.scan_set(source=str(tree), output=str(output), run_id=RUN))

    assert walks == [str(writers_tree), str(other_tree), str(other_tree)], walks
    assert seen[0] == seen[2] == seen[4]
    assert seen[1] == seen[3]
    assert "only_a.py" in _names(seen[4]) and "only_b.py" not in _names(seen[4])
    assert _record(output)["inputs"]["source"] == str(writers_tree)


@pytest.mark.parametrize(
    "respelling",
    [
        lambda tree: str(tree / "extra-rules.txt"),
        lambda tree: "./extra-rules.txt",
        lambda tree: ".//./extra-rules.txt",
    ],
    ids=["absolute", "dot-slash", "repeated-separators"],
)
def test_one_ignore_file_spelled_two_ways_is_read_back(tmp_path, walks, respelling):
    """The ignore file is resolved as the walk resolves it, below the source."""
    tree = _tree(tmp_path / "a", "keep.py", "drop_me.py")
    (tree / "extra-rules.txt").write_text("drop_me.py\n", encoding="utf-8")
    output = tmp_path / "out"

    first = gss.scan_set(
        source=str(tree),
        output=str(output),
        run_id=RUN,
        ignorefile=["extra-rules.txt"],
    )
    second = gss.scan_set(
        source=str(tree),
        output=str(output),
        run_id=RUN,
        ignorefile=[respelling(tree)],
    )

    assert "drop_me.py" not in _names(first), first
    assert second == first
    assert walks == [str(tree)], walks
    assert _record(output)["inputs"]["ignorefile"] == [
        os.path.abspath(str(tree / "extra-rules.txt"))
    ]


def _scan_with_a_dot_dot_spelling(tmp_path):
    """The writer names ``extra-rules.txt``; a second call names it through ``sub/..``.

    ``sub`` is never created. Returns the tree, the output directory and both
    answers.
    """
    tree = _tree(tmp_path / "a", "keep.py", "drop_me.py")
    (tree / "extra-rules.txt").write_text("drop_me.py\n", encoding="utf-8")
    output = tmp_path / "out"

    first = gss.scan_set(
        source=str(tree),
        output=str(output),
        run_id=RUN,
        ignorefile=["extra-rules.txt"],
    )
    second = gss.scan_set(
        source=str(tree),
        output=str(output),
        run_id=RUN,
        ignorefile=["sub/../extra-rules.txt"],
    )
    return tree, output, first, second


def test_a_dot_dot_spelling_is_another_name_so_the_call_walks_again(tmp_path, walks):
    """Control: ``sub/../extra-rules.txt`` is not ``extra-rules.txt``.

    ``..`` is never folded, so the call is one with other ignore files: it walks
    its own tree and leaves the writer's pair and record as they are. This holds
    on every host; what the walk finds through the spelling is the next cell's.
    """
    tree, output, first, _second = _scan_with_a_dot_dot_spelling(tmp_path)

    assert "drop_me.py" not in _names(first), first
    assert walks == [str(tree), str(tree)], walks
    assert _record(output)["inputs"]["ignorefile"] == [
        os.path.abspath(str(tree / "extra-rules.txt"))
    ]
    assert _names(gss.scan_set_this_run_wrote(output, RUN) or []) == _names(first)


@pytest.mark.skipif(
    os.name == "nt",
    reason="Windows folds sub\\.. away before the file system sees the path",
)
def test_a_dot_dot_spelling_through_a_missing_directory_reads_no_file(tmp_path):
    """On POSIX the kernel resolves ``sub`` first, and ``sub`` does not exist, so the
    walk reads no rules from that spelling: ``drop_me.py`` stays in the list."""
    _tree_root, _output, first, second = _scan_with_a_dot_dot_spelling(tmp_path)

    assert "drop_me.py" not in _names(first), first
    assert "drop_me.py" in _names(second), second


def test_ignore_files_named_in_another_order_are_read_back(tmp_path, walks):
    """Order is not compared: the report orders ignore files itself."""
    tree = _tree(tmp_path / "a", "keep.py", "drop_me.py", "drop_too.py")
    (tree / "a-rules.txt").write_text("drop_me.py\n", encoding="utf-8")
    (tree / "b-rules.txt").write_text("drop_too.py\n", encoding="utf-8")
    output = tmp_path / "out"

    first = gss.scan_set(
        source=str(tree),
        output=str(output),
        run_id=RUN,
        ignorefile=["a-rules.txt", "b-rules.txt"],
    )
    second = gss.scan_set(
        source=str(tree),
        output=str(output),
        run_id=RUN,
        ignorefile=["b-rules.txt", "a-rules.txt"],
    )

    assert "keep.py" in _names(first), first
    assert not {"drop_me.py", "drop_too.py"} & set(_names(first)), first
    assert second == first
    assert walks == [str(tree)], walks


def test_an_ignore_file_named_twice_is_one_ignore_file(tmp_path, walks):
    tree = _tree(tmp_path / "a", "keep.py", "drop_me.py")
    (tree / "extra-rules.txt").write_text("drop_me.py\n", encoding="utf-8")
    output = tmp_path / "out"

    first = gss.scan_set(
        source=str(tree),
        output=str(output),
        run_id=RUN,
        ignorefile=["extra-rules.txt"],
    )
    second = gss.scan_set(
        source=str(tree),
        output=str(output),
        run_id=RUN,
        ignorefile=["extra-rules.txt", "./extra-rules.txt"],
    )

    assert second == first
    assert len(walks) == 1, walks


def test_a_relative_ignore_file_is_resolved_below_the_source_not_the_cwd(
    tmp_path, walks, monkeypatch
):
    """Control: the same name below another source is another file, so it walks."""
    first_tree = _tree(tmp_path / "a", "keep.py")
    other_tree = _tree(tmp_path / "b", "keep.py")
    (first_tree / "rules.txt").write_text("keep.py\n", encoding="utf-8")
    (other_tree / "rules.txt").write_text("nothing\n", encoding="utf-8")
    output = tmp_path / "out"
    monkeypatch.chdir(tmp_path)

    first = gss.scan_set(
        source=str(first_tree), output=str(output), run_id=RUN, ignorefile=["rules.txt"]
    )
    other = gss.scan_set(
        source=str(other_tree), output=str(output), run_id=RUN, ignorefile=["rules.txt"]
    )

    assert "keep.py" not in _names(first), first
    assert "keep.py" in _names(other), other
    assert len(walks) == 2, walks


def test_a_pair_changed_since_it_was_written_is_still_the_runs_own(tmp_path, walks):
    """Control: a damaged pair reads as the run's own, not another source's.

    The record names the run and the writer's inputs, so a call for another
    source walks and leaves the damaged pair where it is. Callers read the
    damage as "unknown" (``scan_set_this_run_wrote`` is None), never as the
    other source's list.
    """
    writers_tree = _tree(tmp_path / "a", "only_a.py")
    other_tree = _tree(tmp_path / "b", "only_b.py")
    output = tmp_path / "out"
    gss.scan_set(source=str(writers_tree), output=str(output), run_id=RUN)
    (output / LIST_NAME).write_bytes(b"tampered\n")
    assert gss.scan_set_this_run_wrote(output, RUN) is None

    other = gss.scan_set(source=str(other_tree), output=str(output), run_id=RUN)

    assert "only_b.py" in _names(other), other
    assert (output / LIST_NAME).read_bytes() == b"tampered\n"
    assert gss.scan_set_this_run_wrote(output, RUN) is None
    assert _record(output)["inputs"]["source"] == str(writers_tree)


def test_a_damaged_pair_is_rebuilt_by_a_call_with_the_writers_inputs(tmp_path, walks):
    """Control: damage does not wedge the run; its own inputs write the pair again."""
    writers_tree = _tree(tmp_path / "a", "only_a.py")
    output = tmp_path / "out"
    first = gss.scan_set(source=str(writers_tree), output=str(output), run_id=RUN)
    (output / LIST_NAME).write_bytes(b"tampered\n")

    again = gss.scan_set(source=str(writers_tree), output=str(output), run_id=RUN)

    assert again == first
    assert _names(gss.scan_set_this_run_wrote(output, RUN) or []) == _names(first)
    assert len(walks) == 2, walks


@pytest.mark.skipif(
    sys.platform == "win32", reason="Windows does not allow this character in a name"
)
def test_a_scan_set_holding_a_newline_name_still_owns_its_pair(tmp_path, walks):
    """A pair no list can give back whole is recorded as the run's, not reusable.

    The record's ``sha256`` is null, so nothing reads the pair back, but a call
    of the run for another source still leaves it as the writer wrote it. The
    file with a newline in its name is made by the test under ``tmp_path``;
    POSIX file systems allow it, Windows does not.
    """
    writers_tree = _tree(tmp_path / "a", "only_a.py")
    (writers_tree / "bad\nname.py").write_text("x = 1\n", encoding="utf-8")
    other_tree = _tree(tmp_path / "b", "only_b.py")
    output = tmp_path / "out"

    gss.scan_set(source=str(writers_tree), output=str(output), run_id=RUN)
    pair_before = (output / LIST_NAME).read_bytes()
    assert gss.scan_set_this_run_wrote(output, RUN) is None

    other = gss.scan_set(source=str(other_tree), output=str(output), run_id=RUN)

    assert "only_b.py" in _names(other), other
    assert (output / LIST_NAME).read_bytes() == pair_before
    assert gss.scan_set_this_run_wrote(output, RUN) is None
    assert _record(output)["sha256"] is None
    assert _record(output)["inputs"]["source"] == str(writers_tree)
    assert walks == [str(writers_tree), str(other_tree)], walks


@pytest.mark.parametrize(
    "record",
    [
        {"run_id": RUN},
        {"run_id": RUN, "sha256": "not a mapping"},
        {"run_id": RUN, "inputs": None, "sha256": {}},
        {"run_id": RUN, "inputs": {}, "sha256": {}},
        {"run_id": RUN, "inputs": {"source": "x"}, "sha256": {}},
        {
            "run_id": RUN,
            "inputs": {"source": "x", "source_abs": "x", "ignorefile": []},
        },
    ],
    ids=[
        "run-id-only",
        "digests-not-a-mapping",
        "inputs-null",
        "inputs-empty",
        "inputs-short-of-keys",
        "digests-missing",
    ],
)
def test_a_record_that_is_not_the_shape_scan_set_writes_names_no_owner(
    tmp_path, walks, record
):
    """A record that parses and names the run, but is not an inputs object with a
    digest map or null, is damaged: it owns nothing. The next call, for whatever
    source, walks and writes the pair and a record of its own, and the call after
    that reads them back. Were it taken for an owner, no call of the run could
    write the pair again and every call would walk."""
    first_tree = _tree(tmp_path / "a", "only_a.py")
    other_tree = _tree(tmp_path / "b", "only_b.py")
    output = tmp_path / "out"
    gss.scan_set(source=str(first_tree), output=str(output), run_id=RUN)
    (output / gss.SCAN_SET_RUN_FILE_NAME).write_text(
        json.dumps(record), encoding="utf-8"
    )

    other = gss.scan_set(source=str(other_tree), output=str(output), run_id=RUN)
    again = gss.scan_set(source=str(other_tree), output=str(output), run_id=RUN)

    assert "only_b.py" in _names(other), other
    assert again == other
    assert _record(output)["inputs"]["source"] == str(other_tree)
    assert gss.scan_set_this_run_wrote(output, RUN) == other
    assert walks == [str(first_tree), str(other_tree)], walks
