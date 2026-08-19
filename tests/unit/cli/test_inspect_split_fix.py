"""Regression test: inspect_findings_app uses split('.') not split['.'] (L2)."""

from pathlib import Path

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
    assert '.split["."]' not in source
    assert ".split['.']" not in source
    assert '.split(".")[-1]' in source or ".split('.')[-1]" in source
