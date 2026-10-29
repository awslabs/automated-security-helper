# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A source line read for a finding is masked before it is cut to the snippet cap.

The lines were cut to SNIPPET_LINE_CHARS + 1 characters as they were read, and
masked afterwards: a secret value that started inside the cap and ended past it
was no longer whole in the text the masker saw, so it was not matched and its head
was shown. The cut now follows the masking, and the shown line is still capped.
"""

from unittest.mock import MagicMock

import pytest

from automated_security_helper.cli.inspect.inspect_findings_app import (
    SNIPPET_LINE_CHARS,
    FindingsExplorerApp,
    _cut_excerpt_lines,
    _line_text,
)

pytestmark = pytest.mark.unit

_TOKEN = "hunter2-" * 5


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
