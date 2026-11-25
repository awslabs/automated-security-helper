# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/measure_precommit_cost.py: the fixtures behind the pre-commit cost table.

The table in docs/content/how-to/pre-commit.md is only reproducible if the
repositories it was timed on can be rebuilt. These tests pin that: the same call
writes the same bytes (a digest per fixture), the large fixture really has the
~900 files the column is named for, and it carries content a scanner reports on.
Nothing here times anything.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

SMALL_DIGEST = "ffbd2e49b3745cd1c0cb11cafda6de6c166154d2943f5fb546b812403bb092f3"  # pragma: allowlist secret
LARGE_DIGEST = "dd60607916dbc43a698d5c548e2b3019b296dce709003a1f08002e8a1077057a"  # pragma: allowlist secret


@pytest.fixture
def script(script_loader):
    return script_loader("measure_precommit_cost")


def test_small_fixture_has_ten_python_files_and_a_pinned_digest(script, tmp_path: Path):
    files = script.build_fixture(tmp_path / "s", "small")
    assert len(files) == 10
    assert len(list((tmp_path / "s").rglob("*.py"))) == 10
    assert script.fixture_digest(tmp_path / "s") == SMALL_DIGEST


def test_large_fixture_has_900_python_files_and_a_pinned_digest(script, tmp_path: Path):
    files = script.build_fixture(tmp_path / "l", "large")
    assert len(files) == 900
    assert len(list((tmp_path / "l").rglob("*.py"))) == 900
    assert script.fixture_digest(tmp_path / "l") == LARGE_DIGEST


def test_two_builds_are_byte_identical(script, tmp_path: Path):
    script.build_fixture(tmp_path / "a", "large")
    script.build_fixture(tmp_path / "b", "large")
    assert script.fixture_digest(tmp_path / "a") == script.fixture_digest(
        tmp_path / "b"
    )


def test_digest_changes_when_one_byte_changes(script, tmp_path: Path):
    """Planted control: the digest is not a constant."""
    files = script.build_fixture(tmp_path / "c", "small")
    before = script.fixture_digest(tmp_path / "c")
    files[1].write_text(files[1].read_text(encoding="utf-8") + "#", encoding="utf-8")
    assert script.fixture_digest(tmp_path / "c") != before


def test_large_fixture_carries_scannable_content(script, tmp_path: Path):
    script.build_fixture(tmp_path / "f", "large")
    text = "\n".join(
        p.read_text(encoding="utf-8") for p in (tmp_path / "f").rglob("*.py")
    )
    assert text.count("shell=True") == 10
    assert text.count("PASSWORD = ") == 6


def test_build_refuses_a_non_empty_directory(script, tmp_path: Path):
    (tmp_path / "x").mkdir()
    (tmp_path / "x" / "keep").write_text("1")
    with pytest.raises(ValueError, match="not empty"):
        script.build_fixture(tmp_path / "x", "small")


def test_unknown_kind_is_refused(script, tmp_path: Path):
    with pytest.raises(ValueError, match="unknown fixture kind"):
        script.build_fixture(tmp_path / "y", "medium")


@pytest.mark.parametrize(
    "page",
    ["pre-commit.md", "pre-commit.md.template"],
)
def test_cost_table_names_its_fixture_script_and_venue(page: str):
    """The table's columns come from a rebuildable fixture and a named venue."""
    root = Path(__file__).resolve().parents[3]
    text = (root / "docs" / "content" / "how-to" / page).read_text(encoding="utf-8")
    assert "scripts/measure_precommit_cost.py" in text
    assert "900-file Python repository" in text
    assert "2026-11-25" in text
    assert "earlier\nmeasurement on a different machine" not in text
