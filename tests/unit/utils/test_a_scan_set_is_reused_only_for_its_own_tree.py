# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A run reuses the scan set it wrote only for the tree it was built from.

``get_scan_set.scan_set`` writes the scan set, the ignore report and a record of
the run beside them, and a later call of the same run reads the pair back instead
of walking. The record also names what the list was built from: the source, as
the caller spelled it and made absolute, and the ignore files the caller named. A
call of the run with another source or other ignore files walks its own tree;
reading the first list back gave it the files of another tree.

Both forms of the source must match: the saved list holds paths joined onto the
first caller's spelling, so a caller that spells the directory another way
(relative, absolute) walks its own tree and gets its own spelling, and a relative
spelling from another working directory is another tree.
A call that is not for the first caller's tree answers from its own walk and
leaves the pair and the record as the run's first call wrote them.

The run's settings are not part of that: a list read back is returned as it was
written whatever ``honor_ignore_files`` the reader passes.

Every path here is under ``tmp_path``. The walk is counted by wrapping
``_collect_ignorefiles_and_all_files``.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.utils import get_scan_set as gss

pytestmark = pytest.mark.unit

RUN = "0123456789abcdef" * 2


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


def _on_disk(output: Path) -> dict:
    """The bytes of the pair and of the run record in *output*."""
    return {
        name: (output / name).read_bytes()
        for name in (*gss.SCAN_START_FILE_NAMES, gss.SCAN_SET_RUN_FILE_NAME)
    }


def test_a_call_with_another_source_walks_its_own_tree(tmp_path, walks):
    first_tree = _tree(tmp_path / "a", "only_a.py")
    second_tree = _tree(tmp_path / "b", "only_b.py")
    output = tmp_path / "out"

    first = gss.scan_set(source=str(first_tree), output=str(output), run_id=RUN)
    second = gss.scan_set(source=str(second_tree), output=str(output), run_id=RUN)

    assert "only_a.py" in _names(first), first
    assert "only_b.py" in _names(second), second
    assert "only_a.py" not in _names(second), second
    assert walks == [str(first_tree), str(second_tree)]


def test_a_call_with_other_ignore_files_walks_again(tmp_path, walks):
    tree = _tree(tmp_path / "a", "keep.py", "drop_me.py")
    (tree / "extra-rules.txt").write_text("drop_me.py\n", encoding="utf-8")
    output = tmp_path / "out"

    first = gss.scan_set(source=str(tree), output=str(output), run_id=RUN)
    second = gss.scan_set(
        source=str(tree),
        output=str(output),
        run_id=RUN,
        ignorefile=["extra-rules.txt"],
    )

    assert "drop_me.py" in _names(first), first
    assert "drop_me.py" not in _names(second), second
    assert "keep.py" in _names(second), second
    assert len(walks) == 2, walks


def test_a_call_for_another_source_leaves_the_pair_the_run_wrote(tmp_path, walks):
    """The run's first call owns the pair; another source answers and writes nothing."""
    first_tree = _tree(tmp_path / "a", "only_a.py")
    second_tree = _tree(tmp_path / "b", "only_b.py")
    output = tmp_path / "out"

    first = gss.scan_set(source=str(first_tree), output=str(output), run_id=RUN)
    written = _on_disk(output)
    second = gss.scan_set(source=str(second_tree), output=str(output), run_id=RUN)

    assert "only_b.py" in _names(second), second
    assert _on_disk(output) == written
    assert gss.scan_set_this_run_wrote(output, RUN) == first
    # The first tree still reads its own pair back: no walk for this call.
    third = gss.scan_set(source=str(first_tree), output=str(output), run_id=RUN)
    assert third == first
    assert walks == [str(first_tree), str(second_tree)], walks


def test_a_call_with_other_ignore_files_leaves_the_pair_the_run_wrote(tmp_path, walks):
    tree = _tree(tmp_path / "a", "keep.py", "drop_me.py")
    (tree / "extra-rules.txt").write_text("drop_me.py\n", encoding="utf-8")
    output = tmp_path / "out"

    first = gss.scan_set(source=str(tree), output=str(output), run_id=RUN)
    written = _on_disk(output)
    gss.scan_set(
        source=str(tree),
        output=str(output),
        run_id=RUN,
        ignorefile=["extra-rules.txt"],
    )

    assert _on_disk(output) == written
    assert gss.scan_set_this_run_wrote(output, RUN) == first
    assert "drop_me.py" in _names(first), first


def test_another_run_takes_over_the_pair(tmp_path, walks):
    """Control: only a call of the same run leaves the pair; a new run writes its own."""
    first_tree = _tree(tmp_path / "a", "only_a.py")
    second_tree = _tree(tmp_path / "b", "only_b.py")
    output = tmp_path / "out"
    other_run = "fedcba9876543210" * 2

    gss.scan_set(source=str(first_tree), output=str(output), run_id=RUN)
    second = gss.scan_set(source=str(second_tree), output=str(output), run_id=other_run)

    assert gss.scan_set_this_run_wrote(output, RUN) is None
    assert gss.scan_set_this_run_wrote(output, other_run) == second


def test_the_record_names_the_source_and_the_ignore_files(tmp_path, walks):
    tree = _tree(tmp_path / "a", "keep.py")
    output = tmp_path / "out"

    gss.scan_set(source=str(tree), output=str(output), run_id=RUN)

    record = json.loads(
        (output / gss.SCAN_SET_RUN_FILE_NAME).read_text(encoding="utf-8")
    )
    assert record["run_id"] == RUN
    assert record["inputs"] == {
        "source": str(tree),
        "source_abs": str(tree),
        "ignorefile": [],
    }, record


def test_the_record_holds_a_relative_source_both_as_given_and_made_absolute(
    tmp_path, walks, monkeypatch
):
    _tree(tmp_path / "a", "keep.py")
    output = tmp_path / "out"
    monkeypatch.chdir(tmp_path)

    gss.scan_set(source="a", output=str(output), run_id=RUN)

    record = json.loads(
        (output / gss.SCAN_SET_RUN_FILE_NAME).read_text(encoding="utf-8")
    )
    assert record["inputs"] == {
        "source": "a",
        "source_abs": os.path.abspath(tmp_path / "a"),
        "ignorefile": [],
    }, record


def test_one_relative_spelling_from_two_directories_is_two_sources(
    tmp_path, walks, monkeypatch
):
    """``a`` under two working directories names two trees.

    Both calls give the same spelling, the same output directory and the same run
    ID; only the working directory differs. The second call walks its own tree and
    does not read the first tree's list back.
    """
    _tree(tmp_path / "x", "unused.txt")
    _tree(tmp_path / "x" / "a", "only_x.py")
    _tree(tmp_path / "y", "unused.txt")
    _tree(tmp_path / "y" / "a", "only_y.py")
    output = tmp_path / "out"

    monkeypatch.chdir(tmp_path / "x")
    first = gss.scan_set(source="a", output=str(output), run_id=RUN)
    written = _on_disk(output)
    monkeypatch.chdir(tmp_path / "y")
    second = gss.scan_set(source="a", output=str(output), run_id=RUN)

    assert _names(first) == ["only_x.py"], first
    assert _names(second) == ["only_y.py"], second
    assert walks == ["a", "a"], walks
    assert _on_disk(output) == written


def test_one_relative_spelling_from_one_directory_is_read_back(
    tmp_path, walks, monkeypatch
):
    """Control: the same spelling from the same working directory reuses the list."""
    _tree(tmp_path / "x", "unused.txt")
    _tree(tmp_path / "x" / "a", "only_x.py")
    output = tmp_path / "out"
    monkeypatch.chdir(tmp_path / "x")

    first = gss.scan_set(source="a", output=str(output), run_id=RUN)
    second = gss.scan_set(source="a", output=str(output), run_id=RUN)

    assert second == first
    assert walks == ["a"], walks


def test_one_source_spelled_two_ways_is_two_sources(tmp_path, walks, monkeypatch):
    """The source is compared exactly as given.

    The saved list holds paths joined onto the first caller's spelling, so a caller
    that spells the directory another way walks it and gets paths in its own
    spelling; the saved pair stays the first caller's.
    """
    tree = _tree(tmp_path / "a", "keep.py")
    output = tmp_path / "out"
    monkeypatch.chdir(tmp_path)

    first = gss.scan_set(source="a", output=str(output), run_id=RUN)
    written = _on_disk(output)
    second = gss.scan_set(source=str(tree), output=str(output), run_id=RUN)

    assert walks == ["a", str(tree)], walks
    assert [os.path.isabs(entry) for entry in first] == [False], first
    assert [os.path.isabs(entry) for entry in second] == [True], second
    assert _names(second) == _names(first) == ["keep.py"]
    assert _on_disk(output) == written
    assert gss.scan_set_this_run_wrote(output, RUN) == first


def test_the_same_spelling_is_read_back_in_that_spelling(tmp_path, walks, monkeypatch):
    """Control: a caller that spells the source as the writer did reads its list."""
    _tree(tmp_path / "a", "keep.py")
    output = tmp_path / "out"
    monkeypatch.chdir(tmp_path)

    first = gss.scan_set(source="a", output=str(output), run_id=RUN)
    second = gss.scan_set(source="a", output=str(output), run_id=RUN)

    assert walks == ["a"], walks
    assert second == first
    assert [os.path.isabs(entry) for entry in second] == [False], second


def test_threads_that_finish_walking_together_write_the_pair_once(
    tmp_path, monkeypatch
):
    """Two scanners of one run, each for its own source, reach the write together.

    The threads are this test's own. A barrier inside the walk holds each one until
    the other has finished walking. A second barrier holds each one at the record
    check, with no record on disk, until the other has checked too; it is given a
    second to fill. Where the check and the write are separate steps both threads
    fill it and both write. Where they run under one lock the second thread cannot
    reach the check until the first has written, the barrier times out in the
    first, and the second finds the record. The pair is written once, by one of
    them, and the other answers from its own walk and leaves the pair and the
    record as the first wrote them.
    """
    trees = {
        "a": _tree(tmp_path / "a", "only_a.py"),
        "b": _tree(tmp_path / "b", "only_b.py"),
    }
    output = tmp_path / "out"
    both_walked = threading.Barrier(2, timeout=30)
    both_checked = threading.Barrier(2)
    real_walk = gss._collect_ignorefiles_and_all_files
    real_check = gss._record_names_other_inputs
    real_write = gss._write_lists
    writes: List[str] = []

    def walking_together(path, *args, **kwargs):
        walked = real_walk(path, *args, **kwargs)
        both_walked.wait()
        return walked

    def checking_together(*args, **kwargs):
        answer = real_check(*args, **kwargs)
        try:
            both_checked.wait(timeout=1)
        except threading.BrokenBarrierError:
            pass
        return answer

    def recording_write(
        output_path, ignore_lines, scan_set_lines, run_id, inputs=None, settings=None
    ):
        writes.append(inputs["source"])
        return real_write(
            output_path, ignore_lines, scan_set_lines, run_id, inputs, settings
        )

    monkeypatch.setattr(gss, "_collect_ignorefiles_and_all_files", walking_together)
    monkeypatch.setattr(gss, "_record_names_other_inputs", checking_together)
    monkeypatch.setattr(gss, "_write_lists", recording_write)

    answers: dict = {}
    errors: List[BaseException] = []

    def scan(key: str) -> None:
        try:
            answers[key] = gss.scan_set(
                source=str(trees[key]), output=str(output), run_id=RUN
            )
        except BaseException as error:  # reported by the assertions below
            errors.append(error)

    threads = [threading.Thread(target=scan, args=(key,)) for key in trees]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert not errors, errors
    assert sorted(answers) == ["a", "b"], answers
    assert "only_a.py" in _names(answers["a"]), answers
    assert "only_b.py" in _names(answers["b"]), answers
    assert len(writes) == 1, writes
    winner = next(key for key in trees if writes == [str(trees[key])])
    assert gss.scan_set_this_run_wrote(output, RUN) == answers[winner]


def test_a_list_read_back_is_the_runs_whatever_honor_ignore_files_says(tmp_path, walks):
    """Control: the read-back contract of ``scan_set`` (returned as written)."""
    tree = _tree(tmp_path / "a", "keep.py", "drop_me.py")
    (tree / ".gitignore").write_text("drop_me.py\n", encoding="utf-8")
    output = tmp_path / "out"

    first = gss.scan_set(source=str(tree), output=str(output), run_id=RUN)
    second = gss.scan_set(
        source=str(tree), output=str(output), run_id=RUN, honor_ignore_files=False
    )

    assert "drop_me.py" not in _names(first), first
    assert len(walks) == 1, walks
    assert second == first
