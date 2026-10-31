# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``fix_unused_suppressions`` tolerates what ``lint`` tolerates.

Why this file exists
--------------------
``ash config lint --fix-unused`` lints first and then fixes. Lint reports a
config that does not parse (exit 3), a report it cannot read (a warning), and
guards a null ``global_settings``. The fixer re-read the same inputs with no
guard: the parser's error, ``json.load``'s, or an ``AttributeError`` on the null
escaped as a traceback after lint had already printed its result. The fixer
now returns with nothing changed in each of those cases, and the exit code the
command gives is lint's.
"""

import json
from pathlib import Path

import pytest

from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
    LintSeverity,
)

pytestmark = pytest.mark.unit


def _write(tmp_path: Path, config_text: str) -> tuple[Path, Path]:
    config_path = tmp_path / ".ash" / ".ash.yaml"
    config_path.parent.mkdir(parents=True)
    # Bytes, so the file holds the text as written on Windows too (write_text
    # would turn its "\n" into "\r\n" there, and the fixer keeps the file's
    # own breaks, so ``fixed_content == before`` compared two line endings).
    config_path.write_bytes(config_text.encode("utf-8"))
    reports = tmp_path / ".ash" / "ash_output" / "reports"
    reports.mkdir(parents=True)
    return config_path, reports / "ash.unused-suppressions.json"


GOOD_REPORT = json.dumps(
    {"unused_suppressions": [{"path": "src/a.py", "rule_id": "B101", "reason": "one"}]}
)


def test_the_same_report_comments_out_an_entry_it_lists(tmp_path):
    """The control for the refusals below: with a config and a report that read
    fine, the entry the report lists is commented out. Without it, "nothing was
    fixed" would also be the answer when the report is never found."""
    config_path, report = _write(
        tmp_path,
        "project_name: demo\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: src/a.py\n"
        "      rule_id: B101\n"
        "      reason: one\n",
    )
    report.write_text(GOOD_REPORT, encoding="utf-8")

    fixed_content, fixed_issues, timestamp = ConfigLinter.fix_unused_suppressions(
        config_path
    )

    assert [i.path for i in fixed_issues] == ["global_settings.suppressions[0]"]
    assert timestamp is not None
    assert "# - path: src/a.py" in fixed_content


def test_a_config_that_does_not_parse_is_returned_unchanged(tmp_path):
    """Red at the base: the YAML parser's error escaped."""
    config_path, report = _write(tmp_path, "project_name: [unclosed\n")
    report.write_text(GOOD_REPORT, encoding="utf-8")

    fixed_content, fixed_issues, timestamp = ConfigLinter.fix_unused_suppressions(
        config_path
    )

    assert fixed_issues == []
    assert timestamp is None
    # No content, never an empty string a caller could write over the file.
    assert fixed_content is None


@pytest.mark.parametrize(
    "report_bytes",
    [
        pytest.param(b"# Unused Suppressions Report\n\n## Summary\n", id="markdown"),
        pytest.param(b'{"unused_suppressions": [{"path": "src/a.py"', id="truncated"),
        pytest.param(b"\xff\xfe\x00", id="not-utf8"),
        pytest.param(b"[1, 2, 3]", id="not-an-object"),
    ],
)
def test_a_report_lint_cannot_read_comments_nothing_out(tmp_path, report_bytes):
    """Red at the base: ``json.load`` raised, or ``.get`` on a list did."""
    config_path, report = _write(
        tmp_path,
        "project_name: demo\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: src/a.py\n"
        "      rule_id: B101\n"
        "      reason: one\n",
    )
    report.write_bytes(report_bytes)
    before = config_path.read_bytes().decode("utf-8")

    fixed_content, fixed_issues, _ = ConfigLinter.fix_unused_suppressions(config_path)

    assert fixed_issues == []
    assert fixed_content == before
    result = ConfigLinter.lint(config_path, check_unused=True)
    warnings = [
        i
        for i in result.issues
        if i.category == LintCategory.SUPPRESSION_UNUSED
        and i.severity == LintSeverity.WARNING
    ]
    assert len(warnings) == 1, result.issues
    assert "Failed to read unused suppressions report" in warnings[0].message


def test_a_report_that_is_a_directory_comments_nothing_out(tmp_path):
    config_path, report = _write(
        tmp_path,
        "project_name: demo\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: src/a.py\n"
        "      rule_id: B101\n"
        "      reason: one\n",
    )
    report.mkdir()
    before = config_path.read_bytes().decode("utf-8")

    fixed_content, fixed_issues, _ = ConfigLinter.fix_unused_suppressions(config_path)

    assert fixed_issues == []
    assert fixed_content == before


@pytest.mark.parametrize(
    "config_text",
    [
        pytest.param("project_name: demo\nglobal_settings: null\n", id="null-settings"),
        pytest.param(
            "project_name: demo\nglobal_settings:\n  suppressions: null\n",
            id="null-list",
        ),
        pytest.param("- just\n- a list\n", id="not-a-mapping"),
    ],
)
def test_a_shape_lint_guards_is_returned_unchanged(tmp_path, config_text):
    """Red at the base: ``.get`` on None, or on a list, raised."""
    config_path, report = _write(tmp_path, config_text)
    report.write_text(GOOD_REPORT, encoding="utf-8")
    before = config_path.read_bytes().decode("utf-8")

    fixed_content, fixed_issues, _ = ConfigLinter.fix_unused_suppressions(config_path)

    assert fixed_issues == []
    assert fixed_content == before
