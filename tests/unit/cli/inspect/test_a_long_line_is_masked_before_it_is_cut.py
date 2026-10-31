# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A source line read for a finding is masked before it is cut to the snippet cap,
and a line too long to be read whole is not shown at all.

The lines were cut to SNIPPET_LINE_CHARS + 1 characters as they were read, and
masked afterwards: a secret value that started inside the cap and ended past it
was no longer whole in the text the masker saw, so it was not matched and its head
was shown. The cut now follows the masking, and the shown line is still capped.

The same shape one level down: only the first _LINE_HEAD_BYTES bytes of a line are
kept while reading, so a value that started inside the shown part and ended past
that head still reached the masker cut and its start was shown. A line longer than
its head is now shown as SOURCE_LINE_NOT_SHOWN, and the head is 64 KiB, so only a
minified bundle or a data blob is left out, never a paragraph of prose.
"""

import io
from unittest.mock import MagicMock

import pytest

from automated_security_helper.cli.inspect.inspect_findings_app import (
    _LINE_HEAD_BYTES,
    SNIPPET_LINE_CHARS,
    SOURCE_LINE_NOT_SHOWN,
    FindingsExplorerApp,
    _cut_excerpt_lines,
    _line_text,
    _read_lines,
)

pytestmark = pytest.mark.unit

_TOKEN = "hunter2-" * 5
#: A placeholder value long enough to end past the line head: an ASCII value
#: starting at the cap and this long (65,600 bytes) reaches the masker cut.
_LONG_TOKEN = "hunter2-" * 8200
#: A four-byte character: 16,380 of them take 65,520 of the head's 65,536 bytes,
#: so a 40-character token after them is cut 16 bytes in.
_WIDE = "\U0001f512"
_WIDE_COUNT = (_LINE_HEAD_BYTES - 16) // 4


def test_a_line_is_not_cut_as_it_is_read():
    head = b"a" * (SNIPPET_LINE_CHARS + 99) + b"\n"

    assert len(_line_text(head)) == SNIPPET_LINE_CHARS + 99


def test_the_excerpt_lines_are_cut_after_their_number():
    excerpt = f"→ 1: {'a' * (SNIPPET_LINE_CHARS + 99)}\n  2: short\n"

    cut = _cut_excerpt_lines(excerpt)

    first, second, rest = cut.split("\n")
    assert first == f"→ 1: {'a' * (SNIPPET_LINE_CHARS + 1)}"
    assert second == "  2: short"
    assert rest == ""


def test_a_value_straddling_the_cap_is_masked_whole(tmp_path):
    source = tmp_path / "settings.py"
    # The value starts six characters before the cap and ends past it.
    source.write_text("a" * (SNIPPET_LINE_CHARS - 5) + _TOKEN + "\n", encoding="utf-8")
    finding = {"rule_id": "S105", "file": "settings.py", "line": 1}
    app = FindingsExplorerApp(
        [finding],
        mask_source=lambda uri, first, text: text.replace(_TOKEN, "***"),
        scan_root=tmp_path,
    )
    app.push_screen = MagicMock()

    app._show_detail(finding)

    snippet = finding["code_snippet"]
    assert "***" in snippet, snippet
    assert _TOKEN[:6] not in snippet, snippet
    (line, rest) = snippet.split("\n")
    assert rest == ""
    assert len(line) <= len("→ 1: ") + SNIPPET_LINE_CHARS + 1, len(line)


def _shown_lines(tmp_path, source_text: str, masked: str) -> str:
    """The snippet the detail view builds for line 1 of a file holding
    *source_text*, with *masked* replaced by *** when the masker sees it whole."""
    source = tmp_path / "settings.py"
    source.write_text(source_text, encoding="utf-8")
    finding = {"rule_id": "S105", "file": "settings.py", "line": 1}
    app = FindingsExplorerApp(
        [finding],
        mask_source=lambda uri, first, text: text.replace(masked, "***"),
        scan_root=tmp_path,
    )
    app.push_screen = MagicMock()

    app._show_detail(finding)

    return finding["code_snippet"]


class TestALineLongerThanItsHeadIsNotShown:
    def test_an_ascii_value_ending_past_the_head(self, tmp_path):
        # The value starts six characters before the cap, inside the shown part,
        # and ends past the head, so the masker never saw it whole.
        snippet = _shown_lines(
            tmp_path,
            "a" * (SNIPPET_LINE_CHARS - 5) + _LONG_TOKEN + "\nnext\n",
            _LONG_TOKEN,
        )

        first, second, rest = snippet.split("\n")
        assert first == f"→ 1: {SOURCE_LINE_NOT_SHOWN}", first
        assert _LONG_TOKEN[:6] not in snippet, snippet
        assert second == "  2: next"
        assert rest == ""

    def test_a_short_value_after_multibyte_text(self, tmp_path):
        # The four-byte characters fill all but 16 bytes of the head; the
        # 40-character token after them was cut 16 bytes in, and its first
        # characters were shown.
        snippet = _shown_lines(tmp_path, _WIDE * _WIDE_COUNT + _TOKEN + "\n", _TOKEN)

        line, rest = snippet.split("\n")
        assert line == f"→ 1: {SOURCE_LINE_NOT_SHOWN}", line
        assert _TOKEN[:6] not in snippet, snippet
        assert rest == ""

    def test_a_line_that_fits_its_head_is_shown_and_masked(self, tmp_path):
        # 60,000 + 40 bytes fit the head: the line is masked whole, then cut to
        # the cap, so its head is shown and nothing of the value is. With the
        # earlier 2,004-byte head this line, a long one of ordinary prose or
        # code, was not shown at all.
        snippet = _shown_lines(tmp_path, "a" * 60000 + _TOKEN + "\n", _TOKEN)

        line, rest = snippet.split("\n")
        assert line == "→ 1: " + "a" * (SNIPPET_LINE_CHARS + 1), line
        assert _TOKEN[:6] not in snippet, snippet
        assert SOURCE_LINE_NOT_SHOWN not in snippet, snippet


class TestReadLinesMarksTheLinesItCouldNotKeepWhole:
    def test_a_long_line_among_short_ones(self):
        handle = io.BytesIO(b"short\n" + b"x" * (_LINE_HEAD_BYTES + 1) + b"\nafter\n")

        assert _read_lines(handle, 1, 3) == ["short", SOURCE_LINE_NOT_SHOWN, "after"]

    def test_a_line_of_exactly_the_head_is_kept(self):
        head = b"y" * _LINE_HEAD_BYTES
        handle = io.BytesIO(head + b"\n")

        assert _read_lines(handle, 1, 1) == [head.decode()]

    def test_the_last_line_at_the_files_end_is_kept(self):
        handle = io.BytesIO(b"one\ntwo")

        assert _read_lines(handle, 1, 2) == ["one", "two"]
