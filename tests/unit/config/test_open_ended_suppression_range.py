# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`line_start` without `line_end` matches to end of file, and says so.

Why this file exists
--------------------
The matcher and the linter disagreed. `_line_range_matches` returns
``finding_end >= suppression.line_start`` when no ``line_end`` is set, which
matches every finding from that line onwards. The linter told the user the
opposite: "will default to line_start value", i.e. a single line.

Whichever one you believed, the other was lying. Someone writing
``line_start: 40`` to silence one finding was told they had done exactly that,
while actually suppressing everything from line 40 to the end of the file --
including findings that did not exist yet.

Why the message changed and not the matcher
-------------------------------------------
Narrowing the matcher to a single line is the other way to reconcile them, and
it is a breaking change: every existing single-line suppression would stop
covering the range it covers today, so findings currently suppressed reappear as
actionable on upgrade. Changing the message costs nothing and breaks nobody, so
open-ended matching becomes the documented contract.

That makes the behaviour a decision rather than an accident, which is why the
tests below pin the matcher too. Without them the next person to read
``finding_end >= line_start`` has no way to tell whether it is intended.

The autofix stays, but it is a narrowing
----------------------------------------
Setting ``line_end = line_start`` is still offered, because a single line is
usually what someone wants. It is no longer described as correcting an omission:
applying it *changes* which findings are suppressed, and the description has to
say so or `ash config lint --fix` silently narrows suppressions across a repo.
"""

import textwrap
from pathlib import Path

from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
)
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.suppression_matcher import (
    _line_range_matches,
)


def _write_config(tmp_path: Path) -> Path:
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(
        textwrap.dedent(
            """\
            project_name: open-ended-probe
            global_settings:
              suppressions:
                - path: "src/foo.py"
                  rule_id: "B201"
                  line_start: 40
                  reason: "single finding"
            """
        ),
        encoding="utf-8",
    )
    return config_path


def _range_issue(config_path: Path):
    result = ConfigLinter.lint(config_path)
    matches = [
        issue
        for issue in result.issues
        if issue.category == LintCategory.SUPPRESSION_LINE_RANGE
        and "line_end" in issue.message
    ]
    assert len(matches) == 1, matches
    return matches[0]


def _finding(line: int) -> FlatVulnerability:
    return FlatVulnerability(
        id=f"finding-{line}",
        title="probe",
        description="probe",
        scanner="bandit",
        scanner_type="SAST",
        severity="MEDIUM",
        file_path="src/foo.py",
        line_start=line,
        line_end=line,
    )


class TestTheMatcherIsOpenEnded:
    """Pin the contract, so the behaviour reads as chosen rather than accidental."""

    def test_a_later_finding_is_suppressed(self):
        suppression = AshSuppression(path="src/foo.py", line_start=40, reason="r")

        assert _line_range_matches(_finding(500), suppression) is True

    def test_the_starting_line_is_suppressed(self):
        suppression = AshSuppression(path="src/foo.py", line_start=40, reason="r")

        assert _line_range_matches(_finding(40), suppression) is True

    def test_an_earlier_finding_is_not_suppressed(self):
        """Open-ended forwards, not in both directions."""
        suppression = AshSuppression(path="src/foo.py", line_start=40, reason="r")

        assert _line_range_matches(_finding(39), suppression) is False


class TestTheWarningDescribesWhatHappens:
    def test_the_message_no_longer_claims_a_single_line_default(self, tmp_path):
        issue = _range_issue(_write_config(tmp_path))

        assert "default to line_start" not in issue.message, (
            "The warning still says the range defaults to line_start, which is "
            "the claim that did not match _line_range_matches."
        )

    def test_the_message_says_it_matches_to_the_end_of_the_file(self, tmp_path):
        issue = _range_issue(_write_config(tmp_path))

        lowered = issue.message.lower()
        assert "end of the file" in lowered or "end of file" in lowered, (
            f"The warning does not tell the user the suppression is open-ended: "
            f"{issue.message!r}"
        )

    def test_the_fix_is_described_as_narrowing(self, tmp_path):
        """`--fix` changes which findings are suppressed, so it must say so."""
        issue = _range_issue(_write_config(tmp_path))

        assert issue.fixable is True
        assert "narrow" in issue.fix_description.lower(), (
            f"The fix reads as correcting an omission rather than changing "
            f"behaviour: {issue.fix_description!r}"
        )

    def test_the_fix_still_sets_line_end(self, tmp_path):
        """Rewording must not remove the fix people rely on."""
        config_path = _write_config(tmp_path)

        fixed_content, fixed_issues = ConfigLinter.fix(config_path)

        assert any(
            issue.category == LintCategory.SUPPRESSION_LINE_RANGE
            for issue in fixed_issues
        )
        assert "line_end: 40" in fixed_content
