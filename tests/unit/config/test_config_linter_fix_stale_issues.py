# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``fix`` applies an issue computed earlier only when the file still raises it.

Why this file exists
--------------------
``ash config lint --fix`` lints, prints the fixable issues, asks for
confirmation, and then calls ``ConfigLinter.fix`` with the issues it printed.
``fix`` reads the file again. A suppression issue names its entry by index
(``global_settings.suppressions[2]``), so an entry removed or moved between the
lint and the confirmation made the fix delete, or narrow, whichever entry sat
at that index in the fresh read. ``fix`` now keeps only the given issues the
fresh read raises again.
"""

from pathlib import Path

import pytest
import yaml

from automated_security_helper.config.config_linter import ConfigLinter, LintCategory

pytestmark = pytest.mark.unit


def _write(config_path: Path, suppressions: list) -> None:
    config_path.write_text(
        yaml.safe_dump(
            {
                "project_name": "demo",
                "global_settings": {"suppressions": suppressions},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def test_a_stale_removal_does_not_delete_the_entry_now_at_its_index(tmp_path):
    """Red at the base: the index-addressed removal popped src/keep.py."""
    config_path = tmp_path / ".ash.yaml"
    _write(
        config_path,
        [
            {"path": "src/first.py", "rule_id": "B101", "reason": "keep"},
            {
                "path": "src/expired.py",
                "rule_id": "B102",
                "reason": "old",
                "expiration": "2020-01-01",
            },
            {"path": "src/keep.py", "rule_id": "B103", "reason": "keep too"},
        ],
    )
    issues = ConfigLinter.lint(config_path).fixable_issues
    assert [i.category for i in issues] == [LintCategory.SUPPRESSION_EXPIRED]
    assert issues[0].path == "global_settings.suppressions[1]"

    # Between the lint and the confirmation someone removed the expired entry
    # by hand, so src/keep.py now sits at index 1.
    _write(
        config_path,
        [
            {"path": "src/first.py", "rule_id": "B101", "reason": "keep"},
            {"path": "src/keep.py", "rule_id": "B103", "reason": "keep too"},
        ],
    )

    fixed_content, fixed_issues = ConfigLinter.fix(config_path, issues)

    assert fixed_issues == []
    data = yaml.safe_load(fixed_content)
    assert [s["path"] for s in data["global_settings"]["suppressions"]] == [
        "src/first.py",
        "src/keep.py",
    ]


def test_an_issue_the_file_still_raises_is_applied(tmp_path):
    """The control: nothing changed, so the earlier issue is applied as before."""
    config_path = tmp_path / ".ash.yaml"
    _write(
        config_path,
        [
            {"path": "src/first.py", "rule_id": "B101", "reason": "keep"},
            {
                "path": "src/expired.py",
                "rule_id": "B102",
                "reason": "old",
                "expiration": "2020-01-01",
            },
        ],
    )
    issues = ConfigLinter.lint(config_path).fixable_issues

    fixed_content, fixed_issues = ConfigLinter.fix(config_path, issues)

    assert [i.category for i in fixed_issues] == [LintCategory.SUPPRESSION_EXPIRED]
    data = yaml.safe_load(fixed_content)
    assert [s["path"] for s in data["global_settings"]["suppressions"]] == [
        "src/first.py"
    ]
