# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for inline suppression support (ash-ignore / ash-ignore-next-line)."""

from pathlib import Path
from textwrap import dedent

import pytest

from automated_security_helper.utils.suppression_matcher import (
    InlineSuppression,
    find_inline_suppressions,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_source(tmp_path: Path, content: str) -> Path:
    """Write *content* to a temp file and return its path."""
    p = tmp_path / "sample.py"
    p.write_text(dedent(content), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# find_inline_suppressions
# ---------------------------------------------------------------------------

class TestFindInlineSuppressions:
    """Tests for find_inline_suppressions()."""

    def test_ash_ignore_same_line(self, tmp_path):
        src = _write_source(tmp_path, """\
            x = 1  # ash-ignore: RULE-001 false positive
        """)
        result = find_inline_suppressions(src)
        assert len(result) == 1
        assert result[0] == InlineSuppression(
            line_number=1, rule_id="RULE-001", reason="false positive"
        )

    def test_ash_ignore_next_line(self, tmp_path):
        src = _write_source(tmp_path, """\
            # ash-ignore-next-line: SEC-002 known safe
            password = "hunter2"
        """)
        result = find_inline_suppressions(src)
        assert len(result) == 1
        # The suppression targets line 2 (the line after the comment).
        assert result[0].line_number == 2
        assert result[0].rule_id == "SEC-002"
        assert result[0].reason == "known safe"

    def test_no_suppressions(self, tmp_path):
        src = _write_source(tmp_path, """\
            import os
            print("hello")
        """)
        assert find_inline_suppressions(src) == []

    def test_multiple_directives(self, tmp_path):
        src = _write_source(tmp_path, """\
            x = dangerous("1")  # ash-ignore: DANGEROUS-001 testing
            # ash-ignore-next-line: SQL-INJ reason two
            query = "SELECT *"
            y = 2  # ash-ignore: OTHER-99
        """)
        result = find_inline_suppressions(src)
        assert len(result) == 3
        assert result[0].rule_id == "DANGEROUS-001"
        assert result[0].line_number == 1
        assert result[1].rule_id == "SQL-INJ"
        assert result[1].line_number == 3  # next-line targets line 3
        assert result[2].rule_id == "OTHER-99"
        assert result[2].line_number == 4

    def test_case_insensitive(self, tmp_path):
        src = _write_source(tmp_path, """\
            x = 1  # ASH-IGNORE: rule-1 caps
            # Ash-Ignore-Next-Line: rule-2 mixed
            y = 2
        """)
        result = find_inline_suppressions(src)
        assert len(result) == 2
        assert result[0].rule_id == "rule-1"
        assert result[1].rule_id == "rule-2"

    def test_default_reason_when_omitted(self, tmp_path):
        src = _write_source(tmp_path, """\
            x = 1  # ash-ignore: RULE-X
        """)
        result = find_inline_suppressions(src)
        assert result[0].reason == "Inline suppression"

    def test_default_reason_next_line_when_omitted(self, tmp_path):
        src = _write_source(tmp_path, """\
            # ash-ignore-next-line: RULE-Y
            y = 2
        """)
        result = find_inline_suppressions(src)
        assert result[0].reason == "Inline suppression (next-line)"

    def test_indented_comment(self, tmp_path):
        src = _write_source(tmp_path, """\
            def foo():
                x = 1  # ash-ignore: IND-001 indented
        """)
        result = find_inline_suppressions(src)
        assert len(result) == 1
        assert result[0].rule_id == "IND-001"

    def test_nonexistent_file(self, tmp_path):
        missing = tmp_path / "does_not_exist.py"
        assert find_inline_suppressions(missing) == []

    def test_binary_file_does_not_crash(self, tmp_path):
        binfile = tmp_path / "data.bin"
        binfile.write_bytes(b"\x00\xff\xfe\x80" * 100)
        # Should not raise, returns empty list.
        assert find_inline_suppressions(binfile) == []

    def test_standalone_comment_line(self, tmp_path):
        """A comment on its own line (not trailing code) with ash-ignore
        should still suppress the same line number."""
        src = _write_source(tmp_path, """\
            # ash-ignore: SOLO-001 standalone
        """)
        result = find_inline_suppressions(src)
        assert len(result) == 1
        assert result[0].line_number == 1

    def test_rule_id_with_slashes(self, tmp_path):
        """Rule IDs can contain slashes (e.g. CKV/AWS/123)."""
        src = _write_source(tmp_path, """\
            x = 1  # ash-ignore: CKV/AWS/123 checkov rule
        """)
        result = find_inline_suppressions(src)
        assert result[0].rule_id == "CKV/AWS/123"
