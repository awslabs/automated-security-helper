# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""scripts/check_ty_ratchet.py fails above the ceiling and never passes unmeasured."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "check_ty_ratchet", ROOT / "scripts" / "check_ty_ratchet.py"
)
assert _spec is not None and _spec.loader is not None
ratchet = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ratchet)


def _run(tmp_path: Path, ty_output: str, ceiling: str = "# c\n10\n") -> int:
    out = tmp_path / "ty.txt"
    out.write_text(ty_output, encoding="utf-8")
    ceil = tmp_path / "ceiling.txt"
    ceil.write_text(ceiling, encoding="utf-8")
    return ratchet.main(["x", str(out), str(ceil)])


def test_at_ceiling_passes(tmp_path):
    assert _run(tmp_path, "noise\nFound 10 diagnostics\n") == 0


def test_under_ceiling_passes(tmp_path):
    assert _run(tmp_path, "Found 1 diagnostic\n") == 0


def test_over_ceiling_fails(tmp_path):
    assert _run(tmp_path, "Found 11 diagnostics\n") == 1


def test_zero_diagnostics_passes(tmp_path):
    assert _run(tmp_path, "All checks passed!\n", ceiling="0\n") == 0


def test_no_total_is_not_a_pass(tmp_path):
    assert _run(tmp_path, "error: ty crashed\n") == 2


def test_bad_ceiling_is_not_a_pass(tmp_path):
    assert _run(tmp_path, "Found 1 diagnostic\n", ceiling="# only a comment\n") == 2
    assert _run(tmp_path, "Found 1 diagnostic\n", ceiling="abc\n") == 2


def test_committed_ceiling_is_an_integer():
    assert ratchet.read_ceiling(ROOT / "scripts" / "ty_ceiling.txt") >= 0


def test_workflow_ratchet_step_does_not_continue_on_error():
    text = (ROOT / ".github/workflows/ash-unified-ci.yml").read_text(encoding="utf-8")
    start = text.index('- name: "ty count ratchet')
    step = text[start : text.index("\n      #", start)]
    assert "continue-on-error" not in step
    assert "check_ty_ratchet.py" in step


@pytest.mark.parametrize("bad", ["", "Found diagnostics"])
def test_parse_total_rejects_unmeasured(bad):
    with pytest.raises(ValueError):
        ratchet.parse_total(bad)
