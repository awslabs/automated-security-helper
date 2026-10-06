# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The repository scan's one-line SECRET-* entry on the e2e findings fixture.

``tests/e2e/fixtures/findings/leak.py`` plants AWS's documented example secret
access key so the e2e cases have three detect-secrets findings to assert. Those
scans need the line unmarked, so the repository's own scan suppresses it in
``.ash/.ash.yaml`` by a one-line range instead (see the comment on that entry).

A line range is only as narrow as the line it names: an edit above the line would
move the range onto whatever moved in. So the entry is tied here to the text of
its line, and every other line of the file is shown to stay reportable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.suppression_matcher import (
    should_suppress_finding,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
CONFIG = REPO_ROOT / ".ash" / ".ash.yaml"
FIXTURE = "tests/e2e/fixtures/findings/leak.py"
# The assignment's left-hand side only; the value is not repeated here.
PINNED_PREFIX = "AWS_SECRET_ACCESS_KEY = "
RULES = (
    "SECRET-AWS-ACCESS-KEY",
    "SECRET-BASE64-HIGH-ENTROPY-STRING",
    "SECRET-SECRET-KEYWORD",
)


def fixture_entries() -> list[dict[str, Any]]:
    document = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    return [
        entry
        for entry in document["global_settings"]["suppressions"]
        if entry.get("path") == FIXTURE
    ]


def check_pin(lines: list[str], entries: list[dict[str, Any]]) -> None:
    assert len(entries) == 1, f"expected one entry for {FIXTURE}, found {entries}"
    entry = entries[0]
    hits = [n for n, text in enumerate(lines, 1) if text.startswith(PINNED_PREFIX)]
    assert len(hits) == 1, f"expected the planted assignment once, found {hits}"
    assert entry["line_start"] == entry["line_end"] == hits[0], (
        f"the entry covers lines {entry['line_start']}-{entry['line_end']}, but the "
        f"planted assignment is line {hits[0]}. Move the range with the line."
    )
    assert entry.get("reason", "").strip()


def _finding(path: str, line: int, rule: str) -> FlatVulnerability:
    return FlatVulnerability(
        id=f"detect-secrets-{path}-{line}-{rule}",
        title=rule,
        description="planted",
        severity="HIGH",
        scanner="detect-secrets",
        scanner_type="SECRETS",
        rule_id=rule,
        file_path=path,
        line_start=line,
        line_end=line,
    )


def _lines() -> list[str]:
    return (REPO_ROOT / FIXTURE).read_text(encoding="utf-8").splitlines()


def test_the_pin_names_the_planted_assignment() -> None:
    check_pin(_lines(), fixture_entries())


def test_a_line_moved_under_the_pin_fails() -> None:
    # Negative control for the test above.
    with pytest.raises(AssertionError, match="Move the range"):
        check_pin(["# a new first line", *_lines()], fixture_entries())


@pytest.mark.parametrize("rule", RULES)
def test_only_the_planted_line_is_suppressed(rule: str) -> None:
    suppressions = [AshSuppression(**entry) for entry in fixture_entries()]
    suppressed = [
        line
        for line in range(1, len(_lines()) + 3)
        if should_suppress_finding(_finding(FIXTURE, line, rule), suppressions)[0]
    ]
    assert suppressed == [suppressions[0].line_start]


def test_the_pin_does_not_reach_another_file() -> None:
    suppressions = [AshSuppression(**entry) for entry in fixture_entries()]
    line = suppressions[0].line_start
    assert line is not None
    other = "tests/e2e/fixtures/findings/another.py"
    assert should_suppress_finding(
        _finding(other, line, "SECRET-SECRET-KEYWORD"), suppressions
    ) == (False, None)
