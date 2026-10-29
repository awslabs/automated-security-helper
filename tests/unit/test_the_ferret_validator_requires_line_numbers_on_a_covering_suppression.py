# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ferret pre-push validator fails a keyword hit that only an unpinned suppression covers.

``scripts/validate_ferret_plugin.py`` has a check named SUPPRESSION-COVERAGE. Its job is
to make sure that a line the secret-keyword rule flags is excused by an entry in
``.ash/.ash_community_plugins.yaml`` that names the line (``line_start``), and not by an
entry that excuses the rule for the whole file. A whole-file entry also hides every later
hit in that file, which is why the plugin's development notes ask for line numbers.

The check had one ``fail()`` and it sat inside a branch that runs only when the
suppression has a ``line_start``, so no input could reach it: a hit covered by a
whole-file entry passed both this check and the secret-keyword check.

Each test builds a one-file project tree whose second line is flagged, hands the
validator the suppressions to judge, and runs only the check under test. The cells that
expect a failure sit beside controls on the same tree that expect none: an entry that
names the line, an open-ended range, entries for another rule or path, and a hit with no
suppression at all (the secret-keyword check reports that one, and a test below says so).

Nothing runs in a subprocess and nothing is written outside ``tmp_path``.
"""

import importlib.util
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "validate_ferret_plugin.py"

RULE = "SECRET-SECRET-KEYWORD"
COVERAGE_CHECK = "SUPPRESSION-COVERAGE"
TARGET = "docs/example.md"
FLAGGED_AT = 2

# A line the validator's keyword pattern flags, assembled from two pieces so that this
# file does not contain a keyword assignment of its own.
FLAGGED_LINE = "pass" + "word = 1"


def _entry(**keys):
    """A suppression as the validator's config loader produces it."""
    return {"path": TARGET, "rule_id": RULE, **keys}


@pytest.fixture
def validator(tmp_path, monkeypatch):
    """The validator module, loaded fresh and pointed at a one-file project."""
    spec = importlib.util.spec_from_file_location("ferret_validator_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    target = tmp_path / TARGET
    target.parent.mkdir(parents=True)
    target.write_text("an ordinary line\n" + FLAGGED_LINE + "\n", encoding="utf-8")

    monkeypatch.setattr(module, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(module, "ALL_FILES", [target])
    monkeypatch.setattr(module, "failures", [])
    return module


def _failures_of(validator, name):
    return [found for found in validator.failures if found[0] == name]


def _coverage_failures(validator, suppressions):
    validator.COMMUNITY_SUPPRESSIONS = suppressions
    validator.check_suppression_coverage()
    return _failures_of(validator, COVERAGE_CHECK)


ONLY_WITHOUT_A_LINE_START = {
    "no line numbers": [_entry()],
    "line_end without line_start": [_entry(line_end=5)],
    "range elsewhere in the file and a whole-file entry": [
        _entry(line_start=10, line_end=12),
        _entry(),
    ],
    "path glob without line numbers": [{"path": "docs/*.md", "rule_id": RULE}],
}

WITH_A_LINE_START = {
    "range that names the line": [_entry(line_start=2, line_end=2)],
    "range around the line": [_entry(line_start=1, line_end=3)],
    "open-ended range": [_entry(line_start=2)],
    "range entry first, whole-file entry second": [
        _entry(line_start=2, line_end=2),
        _entry(),
    ],
    "whole-file entry first, range entry second": [
        _entry(),
        _entry(line_start=2, line_end=2),
    ],
}

NOT_COVERING = {
    "no suppressions": [],
    "another rule": [{"path": TARGET, "rule_id": "B404"}],
    "another path": [{"path": "docs/other.md", "rule_id": RULE}],
    "range that misses the line": [_entry(line_start=10, line_end=12)],
}


@pytest.mark.parametrize(
    "suppressions",
    list(ONLY_WITHOUT_A_LINE_START.values()),
    ids=list(ONLY_WITHOUT_A_LINE_START),
)
def test_a_hit_that_only_a_suppression_without_a_line_start_covers_fails(
    validator, suppressions
):
    found = _coverage_failures(validator, suppressions)

    assert len(found) == 1, found
    _name, file, line, message = found[0]
    assert file == Path(TARGET)
    assert line == FLAGGED_AT
    assert "line_start/line_end" in message


@pytest.mark.parametrize(
    "suppressions",
    list(WITH_A_LINE_START.values()),
    ids=list(WITH_A_LINE_START),
)
def test_a_hit_that_a_suppression_with_a_line_start_covers_passes(
    validator, suppressions
):
    assert _coverage_failures(validator, suppressions) == []


@pytest.mark.parametrize(
    "suppressions",
    list(NOT_COVERING.values()),
    ids=list(NOT_COVERING),
)
def test_a_hit_that_no_suppression_covers_is_left_to_the_keyword_check(
    validator, suppressions
):
    assert _coverage_failures(validator, suppressions) == []

    validator.check_secret_keywords()
    reported = _failures_of(validator, RULE)
    assert [(found[1], found[2]) for found in reported] == [(Path(TARGET), FLAGGED_AT)]


@pytest.mark.parametrize(
    ("line_numbers", "reported"),
    [
        ("", 1),
        ("      line_start: 2\n      line_end: 2\n", 0),
    ],
    ids=["entry without line numbers", "entry that names the line"],
)
def test_a_community_config_entry_is_judged_by_its_line_numbers(
    validator, tmp_path, line_numbers, reported
):
    config = tmp_path / ".ash" / ".ash_community_plugins.yaml"
    config.parent.mkdir()
    config.write_text(
        "global_settings:\n"
        "  suppressions:\n"
        f"    - path: {TARGET}\n"
        f"      rule_id: {RULE}\n"
        f"{line_numbers}"
        "      reason: example\n",
        encoding="utf-8",
    )
    validator.COMMUNITY_SUPPRESSIONS = validator.load_community_suppressions()

    validator.check_suppression_coverage()

    assert len(_failures_of(validator, COVERAGE_CHECK)) == reported
