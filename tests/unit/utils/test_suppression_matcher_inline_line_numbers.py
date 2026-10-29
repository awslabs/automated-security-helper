# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Inline suppressions are numbered as the scanners number lines, and one
unreadable path does not end the pass.

Why this file exists
--------------------
``find_inline_suppressions`` numbered directives with ``str.splitlines``, which
also breaks a line at a form feed, a vertical tab, NEL, LINE SEPARATOR,
PARAGRAPH SEPARATOR and the ``\\x1c``-``\\x1e`` separators. A scanner's SARIF
``startLine`` counts line feeds only, so after any such character every
directive was attached to a line the results never name and silently stopped
suppressing.

The same function caught ``OSError`` and ``UnicodeDecodeError`` around the
read. A path with an embedded NUL is refused by the OS layer with a
``ValueError`` before the file is opened, and that one path aborted the whole
SARIF suppression pass.
"""

from pathlib import Path

import pytest

from automated_security_helper.utils.suppression_matcher import (
    InlineSuppression,
    find_inline_suppressions,
)

pytestmark = pytest.mark.unit


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "sample.py"
    path.write_text(text, encoding="utf-8", newline="")
    return path


@pytest.mark.parametrize(
    "separator",
    [
        pytest.param("\x0c", id="form-feed"),
        pytest.param("\x0b", id="vertical-tab"),
        pytest.param(chr(0x85), id="nel"),
        pytest.param(chr(0x2028), id="line-separator"),
        pytest.param(chr(0x2029), id="paragraph-separator"),
        pytest.param("\x1c", id="file-separator"),
    ],
)
def test_a_non_line_feed_separator_does_not_shift_the_line_number(tmp_path, separator):
    """Red at the base: splitlines counted the separator as a line break, so
    the directive on line 2 was numbered 3."""
    source = _write(tmp_path, f"text = 'a{separator}b'\nx = 1  # ash-ignore: R1 why\n")

    found = find_inline_suppressions(source)

    assert found == [InlineSuppression(line_number=2, rule_id="R1", reason="why")]


@pytest.mark.parametrize("line_break", ["\r\n", "\r", "\n"], ids=["crlf", "cr", "lf"])
@pytest.mark.parametrize("with_scan_root", [False, True], ids=["plain", "scan-root"])
def test_every_line_break_kind_counts_once_on_both_read_paths(
    tmp_path, line_break, with_scan_root
):
    """CRLF and a lone CR end a line as LF does, as Python's universal newlines
    (which the Python-based scanners read source through) count them; the
    reason carries no CR; and the bytes path given a scan root numbers the
    same as the plain path."""
    source = _write(
        tmp_path,
        f"x = 1{line_break}# ash-ignore-next-line: R2 known{line_break}y = 2{line_break}",
    )

    found = find_inline_suppressions(source, tmp_path if with_scan_root else None)

    assert found == [InlineSuppression(line_number=3, rule_id="R2", reason="known")]


def test_a_path_the_os_layer_refuses_yields_no_suppressions_and_no_error(tmp_path):
    """Red at the base: ``ValueError: embedded null byte`` escaped."""
    found = find_inline_suppressions(tmp_path / "with\x00nul.py")

    assert found == []
