"""The self-scan's one-line keyword pins on product code name the lines they cover.

Why this exists
---------------
detect-secrets reports SECRET-SECRET-KEYWORD on a few product lines that hold a
name beside a quoted sentence or label, not a value. ``.ash.yaml`` suppresses
each with a one-line range, because each sits at module level, where a
``symbol:`` entry cannot reach.

A line range is only as narrow as the line it names. The entries these replaced
spanned 25 lines each, from the line their construct held in one revision to the
line it held in a later one, and by the time they were read the construct had
moved past both ends: they suppressed nothing they were written for and covered
dozens of unrelated lines. So each pin is tied here to the name its line
defines, and the matcher is shown to leave the lines around it reportable.

What this checks
----------------
* Each pinned line still starts with the variable or table key it was pinned
  for and, where the line holds a sentence, still holds a few of its plain
  words. A row names its line this way, never by the value the scanner
  reports, so this file reports nothing itself.
* A row matches exactly one line of its file. A pin whose line moved fails with
  the line to move it to, and a pin whose line changed fails with a request to
  judge the entry again.
* Every line pin of the rule on these files has a row here, and each entry is a
  single line with a reason.
* Within 25 lines of each pin, and at the first and last lines of its file, the
  matcher suppresses only pinned lines, and a pin covers neither another file
  nor another rule.
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

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
CONFIG = REPO_ROOT / ".ash.yaml"
RULE = "SECRET-SECRET-KEYWORD"

#: How far past the line it named an old entry reached; the lines this close to a
#: pin are the ones a too-wide range would have hidden.
WINDOW = 25

#: (path, pinned line, name, words). The stripped line starts with the name, the
#: variable or table key it defines, and holds the words, a few plain words of
#: its sentence, where it has one. Together they match one line of the file.
PINNED_LINES: tuple[tuple[str, int, str, str | None], ...] = (
    (
        "automated_security_helper/models/flat_frame.py",
        143,
        '"is_secret_detection"',
        "rule-classification flag",
    ),
    (
        "automated_security_helper/plugin_manifests/builtin.py",
        44,
        '"detect-secrets"',
        "options for DetectSecrets",
    ),
    (
        "automated_security_helper/utils/finding_diff.py",
        350,
        '"_secret_detection"',
        "baseline-gate policy flag",
    ),
    (
        "automated_security_helper/utils/finding_diff.py",
        356,
        '"is_secret_detection"',
        "rule-classification flag",
    ),
    (
        "automated_security_helper/utils/finding_identity.py",
        780,
        "SECRET_CORRELATION_PREFIX",
        None,
    ),
    (
        "automated_security_helper/utils/secret_masking.py",
        238,
        "_HARDCODED_PASSWORD_LABEL",
        "Possible hardcoded",
    ),
)
PINNED_FILES = sorted({row[0] for row in PINNED_LINES})
PATHS_AND_LINES = [(row[0], row[1]) for row in PINNED_LINES]
IDS = [f"{Path(row[0]).name}:{row[1]}" for row in PINNED_LINES]


def holds(text: str, name: str, words: str | None) -> bool:
    """Whether a line is the one a row names."""
    stripped = text.strip()
    return stripped.startswith(name) and (words is None or words in stripped)


def line_pins(path: str) -> list[dict[str, Any]]:
    """The config's entries for this rule and file that name a line."""
    document = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    return [
        entry
        for entry in document["global_settings"]["suppressions"]
        if entry.get("rule_id") == RULE
        and entry.get("path") == path
        and entry.get("line_start") is not None
    ]


def pinned_lines_of(path: str) -> set[int]:
    return {row[1] for row in PINNED_LINES if row[0] == path}


def source_lines(path: str) -> list[str]:
    return (REPO_ROOT / path).read_text(encoding="utf-8").splitlines()


def check_pin(
    path: str,
    line: int,
    name: str,
    words: str | None,
    lines: list[str],
    entries: list[dict[str, Any]],
) -> None:
    covering = [entry for entry in entries if entry.get("line_start") == line]
    assert len(covering) == 1, f"{path}: expected one {RULE} entry on line {line}"
    entry = covering[0]
    assert entry.get("line_end") == line, f"{path}:{line}: {entry}"
    assert str(entry.get("reason") or "").strip(), f"{path}:{line}: no reason"
    hits = [n for n, text in enumerate(lines, 1) if holds(text, name, words)]
    if hits == [line]:
        return
    if line in hits:
        raise AssertionError(
            f"{path}: the row for line {line} matches lines {hits}. Add words to "
            "the row so it names one line."
        )
    if len(hits) == 1:
        raise AssertionError(
            f"{path}: the line the entry on line {line} was written for is now "
            f"line {hits[0]}. Move the range with the line, and its row in "
            "PINNED_LINES."
        )
    raise AssertionError(
        f"{path}: line {line} no longer holds {name}, and {len(hits)} other "
        "lines do. Read the line, judge the entry again, then update its row or "
        "remove the entry."
    )


def _finding(path: str, line: int, rule: str = RULE) -> FlatVulnerability:
    return FlatVulnerability(
        id=f"detect-secrets-{path}-{line}",
        title=rule,
        description="planted",
        severity="CRITICAL",
        scanner="detect-secrets",
        scanner_type="SECRETS",
        rule_id=rule,
        file_path=path,
        line_start=line,
        line_end=line,
    )


def _suppressions(path: str) -> list[AshSuppression]:
    return [AshSuppression(**entry) for entry in line_pins(path)]


@pytest.mark.parametrize("path, line, name, words", PINNED_LINES, ids=IDS)
def test_each_pin_names_the_line_it_was_written_for(
    path: str, line: int, name: str, words: str | None
) -> None:
    check_pin(path, line, name, words, source_lines(path), line_pins(path))


@pytest.mark.parametrize("path, line, name, words", PINNED_LINES, ids=IDS)
def test_a_line_moved_under_a_pin_fails_with_the_line_to_use(
    path: str, line: int, name: str, words: str | None
) -> None:
    # Negative control for the test above: a line inserted at the top of the file
    # moves the pinned line down one, and the unchanged entry is rejected with the
    # new line number.
    shifted = ["# a new first line", *source_lines(path)]
    with pytest.raises(AssertionError, match=rf"now line {line + 1}\. Move the range"):
        check_pin(path, line, name, words, shifted, line_pins(path))


@pytest.mark.parametrize("path, line, name, words", PINNED_LINES, ids=IDS)
def test_a_line_rewritten_under_a_pin_fails_and_asks_for_a_new_judgment(
    path: str, line: int, name: str, words: str | None
) -> None:
    lines = source_lines(path)
    lines[line - 1] = "# the pinned line, rewritten"
    with pytest.raises(AssertionError, match="judge the entry again"):
        check_pin(path, line, name, words, lines, line_pins(path))


@pytest.mark.parametrize("path, line, name, words", PINNED_LINES, ids=IDS)
def test_a_row_that_matches_a_second_line_fails(
    path: str, line: int, name: str, words: str | None
) -> None:
    # A copy of the pinned line elsewhere in the file would leave the row unable
    # to say which line moved.
    lines = source_lines(path)
    lines.append(lines[line - 1])
    with pytest.raises(AssertionError, match="Add words to the row"):
        check_pin(path, line, name, words, lines, line_pins(path))


@pytest.mark.parametrize("path", PINNED_FILES, ids=lambda path: Path(path).name)
def test_every_line_pin_of_the_rule_on_these_files_has_a_row(path: str) -> None:
    pinned = {entry["line_start"] for entry in line_pins(path)}
    assert pinned == pinned_lines_of(path), (
        f"{path}: the config pins lines {sorted(pinned)}, and the rows here name "
        f"{sorted(pinned_lines_of(path))}. Give each pin a row, or remove the pin."
    )


@pytest.mark.parametrize("path, line", PATHS_AND_LINES, ids=IDS)
def test_the_lines_around_a_pin_are_still_reported(path: str, line: int) -> None:
    suppressions = _suppressions(path)
    last = len(source_lines(path))
    probed = set(range(max(1, line - WINDOW), min(last, line + WINDOW) + 1))
    probed |= {1, last, last + 1}
    suppressed = {
        probe
        for probe in probed
        if should_suppress_finding(_finding(path, probe), suppressions)[0]
    }
    assert suppressed == probed & pinned_lines_of(path)


@pytest.mark.parametrize("path, line", PATHS_AND_LINES, ids=IDS)
def test_a_pin_covers_neither_another_file_nor_another_rule(
    path: str, line: int
) -> None:
    suppressions = _suppressions(path)
    assert should_suppress_finding(_finding(path, line), suppressions)[0]
    other_file = "automated_security_helper/utils/another_module.py"
    assert should_suppress_finding(_finding(other_file, line), suppressions) == (
        False,
        None,
    )
    other_rule = "SECRET-HEX-HIGH-ENTROPY-STRING"
    assert should_suppress_finding(_finding(path, line, other_rule), suppressions) == (
        False,
        None,
    )
