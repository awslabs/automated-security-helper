"""The two ferret-scan entries on the operator's auth module stay on their lines.

ferret-scan's keyword-assignment heuristic reports API_KEY_OR_SECRET at HIGH on
one line of ``ash_operator/auth.py`` (the local that holds the projected service
account token) and one line of its test (the placeholder the test writes as that
token). ``.ash/.ash_community_plugins.yaml`` suppresses each by a one-line range.

A line range is only as narrow as the line it names. If an edit above the line
moves it, the range sits on whatever moved in and hides that instead. So each
entry is tied here to the text of its line, and the matcher is shown to leave
every other line of both files reportable. The real-scan half, ferret-scan
against planted secrets, is tests/integration/test_operator_auth_ferret_pins_scan.py.
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
CONFIG = REPO_ROOT / ".ash" / ".ash_community_plugins.yaml"
RULE = "API_KEY_OR_SECRET"

# path -> the exact text, leading whitespace stripped, of the one line ferret
# reports in that file. Each is stored split inside the keyword so that ferret,
# which scans this file too, does not read the expected text as an assignment.
_AUTH_LINE = ("tok", "en = token_file.read_text().strip()")
_TEST_LINE = (
    "directory = write_service_account(tmp_path, tok",
    'en="the-projected-token\\n")',
)
PINNED_LINES = {
    "deploy/kubernetes-operator/ash_operator/auth.py": "".join(_AUTH_LINE),
    "deploy/kubernetes-operator/tests/test_auth.py": "".join(_TEST_LINE),
}


def entries_for(path: str, config_text: str | None = None) -> list[dict[str, Any]]:
    document = yaml.safe_load(
        CONFIG.read_text(encoding="utf-8") if config_text is None else config_text
    )
    return [
        entry
        for entry in document["global_settings"]["suppressions"]
        if entry.get("path") == path and entry.get("rule_id") == RULE
    ]


def pinned_line_number(path: str, lines: list[str]) -> int:
    hits = [n for n, text in enumerate(lines, 1) if text.strip() == PINNED_LINES[path]]
    assert len(hits) == 1, f"{path}: expected the pinned text once, found it at {hits}"
    return hits[0]


def check_pin(path: str, lines: list[str], entries: list[dict[str, Any]]) -> None:
    assert len(entries) == 1, f"{path}: expected one {RULE} entry, found {entries}"
    entry = entries[0]
    assert entry["line_start"] == entry["line_end"], entry
    assert entry["line_start"] == pinned_line_number(path, lines), (
        f"{path}: the entry covers line {entry['line_start']}, but the line ferret "
        f"reports is now line {pinned_line_number(path, lines)}. Move the range "
        "with the line, or remove the entry if the line is gone."
    )
    assert entry.get("reason", "").strip()


def _finding(path: str, line: int) -> FlatVulnerability:
    return FlatVulnerability(
        id=f"ferret-{path}-{line}",
        title=RULE,
        description="planted",
        severity="HIGH",
        scanner="ferret-scan",
        scanner_type="SECRETS",
        rule_id=RULE,
        file_path=path,
        line_start=line,
        line_end=line,
    )


@pytest.mark.parametrize("path", sorted(PINNED_LINES))
def test_each_pin_names_the_line_ferret_reports(path: str) -> None:
    lines = (REPO_ROOT / path).read_text(encoding="utf-8").splitlines()
    check_pin(path, lines, entries_for(path))


@pytest.mark.parametrize("path", sorted(PINNED_LINES))
def test_a_line_moved_under_the_pin_fails(path: str) -> None:
    # Negative control for the test above: one line inserted at the top of the
    # file moves the pinned line down, and the unchanged entry must be rejected.
    lines = (REPO_ROOT / path).read_text(encoding="utf-8").splitlines()
    shifted = ["# a new first line"] + lines
    with pytest.raises(AssertionError, match="Move the range"):
        check_pin(path, shifted, entries_for(path))


@pytest.mark.parametrize("path", sorted(PINNED_LINES))
def test_every_other_line_is_still_reported(path: str) -> None:
    suppressions = [AshSuppression(**entry) for entry in entries_for(path)]
    line_count = len((REPO_ROOT / path).read_text(encoding="utf-8").splitlines())
    pinned = suppressions[0].line_start
    suppressed = [
        line
        for line in range(1, line_count + 2)
        if should_suppress_finding(_finding(path, line), suppressions)[0]
    ]
    assert suppressed == [pinned]


@pytest.mark.parametrize("path", sorted(PINNED_LINES))
def test_the_pins_do_not_reach_another_file(path: str) -> None:
    suppressions = [AshSuppression(**entry) for entry in entries_for(path)]
    pinned = suppressions[0].line_start
    assert pinned is not None
    other = "deploy/kubernetes-operator/ash_operator/other.py"
    assert should_suppress_finding(_finding(other, pinned), suppressions) == (
        False,
        None,
    )
