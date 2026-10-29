"""Regression test: inspect_findings_app uses split('.') not split['.'].

The call it guarded was in the detail view's Markdown fallback, which built the
code fence's language from the file name. The view does not build Markdown,
so that fallback is gone, and what remains to check is that the subscript form
never comes back.
"""

from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_inspect_findings_split_uses_call_not_subscript():
    source_path = (
        REPO_ROOT
        / "automated_security_helper"
        / "cli"
        / "inspect"
        / "inspect_findings_app.py"
    )
    # Explicit encoding: package source is UTF-8, but read_text() defaults to the
    # locale codepage, which breaks on Windows for non-ASCII sources.
    source = source_path.read_text(encoding="utf-8")
    assert "class FindingDetailScreen" in source, source_path
    assert '.split["."]' not in source
    assert ".split['.']" not in source
