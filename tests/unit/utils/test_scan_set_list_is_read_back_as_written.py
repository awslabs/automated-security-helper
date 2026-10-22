# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan-set list a run reads back is the list it wrote, name for name.

``scan_set`` writes ``ash-scan-set-files-list.txt`` and ``ash-ignore-report.txt``
and records, under the run's ID, the SHA-256 of each in ``ash-scan-set-run.json``;
a later call of the same run reads the pair back instead of walking the tree.

A record holding the digest of the file as it is on disk after the replace, not
of what this run wrote, would let another run replacing the list between the
write and the digest have its list recorded under this run's ID, and read back
as this run's, with no walk. The list is encoded once, and those bytes are
written and digested.

The read-back splits on ``\\n`` alone; ``str.splitlines`` also splits on
``\\x0b``, ``\\x0c``, ``\\x1c``-``\\x1e``, ``\\x85``, U+2028, U+2029 and ``\\r``,
so through it a file named ``a\\x0cb.py`` would come back as ``a`` and ``b.py``.
A name holding ``\\n`` cannot come back whole from a newline-separated list, so a
run whose scan set holds one writes no record, and every later call walks. A name
that is not UTF-8, which ``os.walk`` spells with surrogate escapes, would make a
text-mode write raise ``UnicodeEncodeError`` and ``scan_set`` fail for any tree
holding one; its bytes are written as the filesystem holds them.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.utils import atomic_write
from automated_security_helper.utils import get_scan_set as gss
from automated_security_helper.utils.get_scan_set import scan_set

SCAN_SET_LIST = "ash-scan-set-files-list.txt"
RUN_RECORD = "ash-scan-set-run.json"
RUN_A = "a" * 32

# Built with chr() so that the source file holds no such character itself.
LINE_SEPARATOR = chr(0x2028)
PARAGRAPH_SEPARATOR = chr(0x2029)

#: Windows refuses control characters in a file name.
POSIX_NAMES_ONLY = pytest.mark.skipif(
    sys.platform == "win32", reason="Windows does not allow this character in a name"
)


def _tree(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "src"
    source.mkdir()
    for name in ("app.py", "other.py"):
        (source / name).write_text("x = 1\n", encoding="utf-8")
    return source, tmp_path / "out"


def _names(files) -> set[str]:
    return {Path(f).name for f in files}


def _no_walk():
    return patch.object(
        gss,
        "_collect_ignorefiles_and_all_files",
        side_effect=AssertionError("walked the tree"),
    )


def test_a_list_another_writer_replaced_after_this_run_wrote_it_is_not_read(tmp_path):
    """Another run on the same output directory replaces the list right after this
    run's replace. The record must name the digest of what this run wrote, so the
    read-back sees the change and walks, instead of taking the other run's list as
    this run's."""
    source, output = _tree(tmp_path)
    other_runs_list = str(source / "planted.py").encode("utf-8")
    real_replace = atomic_write._replace

    def _replace_then_another_run_replaces_the_list(staging, target):
        real_replace(staging, target)
        if Path(target).name == SCAN_SET_LIST:
            Path(target).write_bytes(other_runs_list)

    with patch.object(
        atomic_write,
        "_replace",
        side_effect=_replace_then_another_run_replaces_the_list,
    ):
        written = scan_set(source=str(source), output=str(output), run_id=RUN_A)

    # The interleaving happened: the file on disk is the other run's.
    assert (output / SCAN_SET_LIST).read_bytes() == other_runs_list
    found = scan_set(source=str(source), output=str(output), run_id=RUN_A)

    assert found == written
    assert _names(found) == {"app.py", "other.py"}


def test_the_recorded_digest_is_of_the_bytes_written(tmp_path):
    """The bytes are the names joined by newlines, with no newline translation, so
    the list a Windows run writes is the list a POSIX run writes."""
    source, output = _tree(tmp_path)

    written = scan_set(source=str(source), output=str(output), run_id=RUN_A)

    data = (output / SCAN_SET_LIST).read_bytes()
    assert data == "\n".join(written).encode("utf-8")
    assert b"\r" not in data
    record = json.loads((output / RUN_RECORD).read_text(encoding="utf-8"))
    assert record["sha256"][SCAN_SET_LIST] == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize(
    "name",
    [
        pytest.param("a\x0bb.py", id="vertical-tab", marks=POSIX_NAMES_ONLY),
        pytest.param("a\x0cb.py", id="form-feed", marks=POSIX_NAMES_ONLY),
        pytest.param("a\x1cb.py", id="file-separator", marks=POSIX_NAMES_ONLY),
        pytest.param("a\x1db.py", id="group-separator", marks=POSIX_NAMES_ONLY),
        pytest.param("a\x1eb.py", id="record-separator", marks=POSIX_NAMES_ONLY),
        pytest.param("a\rb.py", id="carriage-return", marks=POSIX_NAMES_ONLY),
        pytest.param("a\x85b.py", id="next-line"),
        pytest.param(f"a{LINE_SEPARATOR}b.py", id="line-separator"),
        pytest.param(f"a{PARAGRAPH_SEPARATOR}b.py", id="paragraph-separator"),
    ],
)
def test_a_name_holding_a_line_boundary_is_read_back_whole(tmp_path, name):
    source, output = _tree(tmp_path)
    (source / name).write_text("x = 1\n", encoding="utf-8")
    written = scan_set(source=str(source), output=str(output), run_id=RUN_A)
    assert str(source / name) in written, written

    with _no_walk():
        found = scan_set(source=str(source), output=str(output), run_id=RUN_A)

    assert found == written


def test_an_empty_scan_set_is_read_back_empty(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    assert scan_set(source=str(source), output=str(output), run_id=RUN_A) == []

    with _no_walk():
        assert scan_set(source=str(source), output=str(output), run_id=RUN_A) == []


@POSIX_NAMES_ONLY
def test_a_name_holding_a_newline_is_never_read_back_split(tmp_path):
    """No newline-separated list can carry it, so the run records nothing and the
    next call walks: it gets the name whole."""
    source, output = _tree(tmp_path)
    name = "a\nb.py"
    (source / name).write_text("x = 1\n", encoding="utf-8")
    written = scan_set(source=str(source), output=str(output), run_id=RUN_A)
    assert str(source / name) in written, written

    found = scan_set(source=str(source), output=str(output), run_id=RUN_A)

    assert found == written
    assert not (output / RUN_RECORD).exists()


@pytest.mark.skipif(
    sys.platform in ("win32", "darwin"),
    reason="a name that is not UTF-8 needs a filesystem that stores raw bytes",
)
def test_a_name_that_is_not_utf8_is_written_and_read_back_whole(tmp_path):
    """os.walk spells such a name with surrogate escapes. The list holds its bytes,
    as git and the shell spell it, and the read-back gives the same name."""
    source, output = _tree(tmp_path)
    raw = os.fsencode(str(source)) + b"/caf\xe9.py"
    with open(raw, "wb") as handle:
        handle.write(b"x = 1\n")
    name = os.fsdecode(raw)

    written = scan_set(source=str(source), output=str(output), run_id=RUN_A)
    assert name in written, written
    assert raw in (output / SCAN_SET_LIST).read_bytes()

    with _no_walk():
        found = scan_set(source=str(source), output=str(output), run_id=RUN_A)

    assert found == written


def test_write_bytes_atomically_writes_the_bytes_as_given(tmp_path):
    target = tmp_path / "list.txt"
    target.write_bytes(b"old\n")
    data = "one\ntwo\r\nthree\x0c".encode("utf-8")

    atomic_write.write_bytes_atomically(target, data)

    assert target.read_bytes() == data
    assert [p.name for p in tmp_path.iterdir()] == ["list.txt"]


#: Windows drops a space at the end of a name.
NO_TRAILING_SPACE_ON_WINDOWS = pytest.mark.skipif(
    sys.platform == "win32", reason="Windows drops a trailing space from a name"
)


@pytest.mark.parametrize(
    "name",
    [
        pytest.param(
            "trailing-space.py ",
            id="trailing-space",
            marks=NO_TRAILING_SPACE_ON_WINDOWS,
        ),
        pytest.param("trailing-tab.py\t", id="trailing-tab", marks=POSIX_NAMES_ONLY),
        pytest.param(
            "trailing-cr.py\r", id="trailing-carriage-return", marks=POSIX_NAMES_ONLY
        ),
    ],
)
def test_a_name_ending_in_whitespace_is_returned_exactly(tmp_path, name):
    """The walk and the read-back return the name the file has. Nothing is
    stripped, so the result never names a file that does not exist, or a
    different one."""
    source, output = _tree(tmp_path)
    (source / name).write_text("x = 1\n", encoding="utf-8")

    written = scan_set(source=str(source), output=str(output), run_id=RUN_A)
    assert str(source / name) in written, written
    assert all(os.path.lexists(item) for item in written), written

    with _no_walk():
        found = scan_set(source=str(source), output=str(output), run_id=RUN_A)
    assert found == written
    assert gss.scan_set_this_run_wrote(output, RUN_A) == written


def test_a_relative_source_whose_name_starts_with_a_space_keeps_it(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    (tmp_path / " src").mkdir()
    (tmp_path / " src" / "app.py").write_text("x = 1\n", encoding="utf-8")

    written = scan_set(source=" src", output=str(tmp_path / "out"), run_id=RUN_A)

    assert written == [os.path.join(" src", "app.py")]


@pytest.mark.parametrize(
    ("platform", "data", "names"),
    [
        ("linux", b"a.py\nb.py", ["a.py", "b.py"]),
        ("linux", b"a.py \nb.py\t", ["a.py ", "b.py\t"]),
        ("linux", b"a.py\r\nb.py\r", ["a.py\r", "b.py\r"]),
        ("win32", b"a.py\r\nb.py\r", ["a.py", "b.py"]),
        ("win32", b"a.py \nb.py", ["a.py ", "b.py"]),
        ("win32", b"a\rb.py", ["a\rb.py"]),
    ],
)
def test_a_record_loses_only_its_separator(platform, data, names):
    """A carriage return ends a record only where no file name holds one."""
    with patch.object(gss.sys, "platform", platform):
        assert gss._list_lines(data) == names


def test_write_bytes_atomically_leaves_no_staging_file_when_the_replace_fails(
    tmp_path,
):
    target = tmp_path / "list.txt"
    target.write_bytes(b"old\n")

    with patch.object(atomic_write, "_replace", side_effect=OSError("refused")):
        with pytest.raises(OSError, match="refused"):
            atomic_write.write_bytes_atomically(target, b"new\n")

    assert target.read_bytes() == b"old\n"
    assert [p.name for p in tmp_path.iterdir()] == ["list.txt"]
