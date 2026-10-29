# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The lines the explorer reads from a finding's file are numbered as the scanners
number them: a lone carriage return ends a line too.

The reader counted ``\\n`` alone, while scanners and the results' secret masking
count universal newlines (``\\r\\n``, ``\\n`` and a lone ``\\r``). In a file with a
lone carriage return, the arrow then marked a line other than the one the finding
names, and the lines after the return were numbered one less than the finding's.
"""

import io

import pytest

from automated_security_helper.cli.inspect.inspect_findings_app import (
    _LINE_HEAD_BYTES,
    _READ_CHUNK,
    _offset_of_line,
    _read_lines,
    _source_excerpt,
)

pytestmark = pytest.mark.unit

_BUDGET = 1 << 20


class TestOffsetOfLine:
    def test_a_lone_carriage_return_ends_a_line(self):
        handle = io.BytesIO(b"a\rb\nc\r\nd")

        assert _offset_of_line(handle, 1, _BUDGET) == 0
        handle.seek(0)
        assert _offset_of_line(handle, 2, _BUDGET) == 2
        handle.seek(0)
        assert _offset_of_line(handle, 3, _BUDGET) == 4
        handle.seek(0)
        assert _offset_of_line(handle, 4, _BUDGET) == 7

    def test_a_carriage_return_newline_pair_split_by_a_chunk_is_one_end(self):
        handle = io.BytesIO(b"x" * (_READ_CHUNK - 1) + b"\r\n" + b"y\n")

        assert _offset_of_line(handle, 2, _BUDGET) == _READ_CHUNK + 1
        handle.seek(0)
        assert _offset_of_line(handle, 3, _BUDGET) == _READ_CHUNK + 3

    def test_a_lone_carriage_return_at_a_chunk_end_is_one_end(self):
        handle = io.BytesIO(b"x" * (_READ_CHUNK - 1) + b"\r" + b"y\n")

        assert _offset_of_line(handle, 2, _BUDGET) == _READ_CHUNK


class TestReadLines:
    def test_lines_are_split_at_every_line_end(self):
        handle = io.BytesIO(b"a\rb\nc\r\nd\n")

        assert _read_lines(handle, 1, 4) == ["a", "b", "c", "d"]

    def test_a_range_inside_the_file(self):
        handle = io.BytesIO(b"a\rb\rc\rd\re")

        assert _read_lines(handle, 2, 4) == ["b", "c", "d"]

    def test_a_lone_carriage_return_at_a_chunk_end_splits_the_lines(self):
        handle = io.BytesIO(b"x" * (_READ_CHUNK - 1) + b"\r" + b"y\n")

        lines = _read_lines(handle, 1, 2)

        assert len(lines) == 2, lines
        assert lines[1] == "y"
        # Only the head of the long line is kept.
        assert len(lines[0]) == _LINE_HEAD_BYTES

    def test_a_line_longer_than_a_chunk_keeps_its_head_only(self):
        handle = io.BytesIO(b"x" * (3 * _READ_CHUNK) + b"\ny\n")

        lines = _read_lines(handle, 1, 2)

        assert len(lines) == 2, len(lines)
        assert len(lines[0]) == _LINE_HEAD_BYTES
        assert lines[1] == "y"


def test_the_arrow_marks_the_line_the_finding_names(tmp_path):
    (tmp_path / "old.py").write_bytes(b"first\rsecond\rthird\n")

    excerpt = _source_excerpt({"file": "old.py", "line": 2}, tmp_path)

    assert excerpt is not None
    assert "→ 2: second\n" in excerpt, excerpt
    assert "  1: first\n" in excerpt and "  3: third\n" in excerpt, excerpt
