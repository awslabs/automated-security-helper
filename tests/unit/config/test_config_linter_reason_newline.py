# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A suppression `reason` containing a newline is a reporting hazard.

Why this file exists
--------------------
The unused-suppressions reporter emits the reason as one markdown bullet
(`- **Reason**: {reason}` in unused_suppressions_reporter.py), so an embedded
newline ends the bullet and everything after it renders as loose body text,
detached from the suppression it belongs to. Nothing caught this:
`AshSuppression.reason` is a plain `str` with no content validation, and
`ash config validate` reported "Configuration is valid!".

The issue describes this as a broken markdown *table* row. That is close but not
where it happens -- grepping the reporters shows `reason` is never rendered into
a table, only into that bullet. The failure is the same either way, and so is
the fix, but the check message names the bullet so a reader is not sent looking
for a table.

Interior newlines only
----------------------
A YAML block scalar always ends with a newline under default clip chomping, so
`reason: >` and a single-line `reason: |` both produce a trailing newline while
rendering perfectly well. The check strips before looking, otherwise it would
warn on the common case for no benefit.

Why lint rather than reject
---------------------------
The config is not *invalid* -- block scalars are a reasonable way to write a long
justification, and rejecting them outright would break configs that work fine
for every consumer other than that one reporter. So this is a fixable warning,
matching how the linter already treats a missing `line_end`: tell the user, and
collapse it for them under `--fix`.

Collapsing rather than escaping is deliberate. The reason is prose meant for a
human reading a report, so whitespace carries no meaning worth preserving, and a
single space keeps it readable in the one place it renders. Escaping to `<br>`
would leak markdown into a field that also appears in JSON and SARIF output.
"""

import textwrap
from pathlib import Path

import pytest

from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
    LintSeverity,
)


def _write_config(tmp_path: Path, suppressions_yaml: str) -> Path:
    body = textwrap.indent(textwrap.dedent(suppressions_yaml).rstrip("\n"), " " * 4)
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text(
        "project_name: reason-newline-probe\n"
        "global_settings:\n"
        "  suppressions:\n" + body + "\n",
        encoding="utf-8",
    )
    return config_path


def _reason_issues(config_path: Path):
    result = ConfigLinter.lint(config_path)
    return [
        issue
        for issue in result.issues
        if issue.category == LintCategory.SUPPRESSION_MULTILINE_REASON
    ]


class TestMultilineReasonIsFlagged:
    def test_block_scalar_reason_is_flagged(self, tmp_path):
        """The exact shape from the issue report: a `|` block scalar."""
        config_path = _write_config(
            tmp_path,
            """\
            - path: "src/foo.py"
              rule_id: "B201"
              reason: |
                Multi-line reason
                with a newline.
            """,
        )

        issues = _reason_issues(config_path)

        assert len(issues) == 1
        assert issues[0].severity == LintSeverity.WARNING
        assert issues[0].fixable is True
        assert "global_settings.suppressions[0]" == issues[0].path

    def test_single_line_reason_is_not_flagged(self, tmp_path):
        config_path = _write_config(
            tmp_path,
            """\
            - path: "src/foo.py"
              rule_id: "B201"
              reason: "A perfectly ordinary reason"
            """,
        )

        assert _reason_issues(config_path) == []

    def test_folded_scalar_reason_is_not_flagged(self, tmp_path):
        """`>` folds the interior newlines but still leaves a trailing one.

        The loaded value here is "...source lines.\\n", so a naive `"\\n" in
        reason` check flags it. It renders correctly, because a trailing newline
        just ends the bullet where the bullet was going to end anyway. This
        passes because the check strips first, and that is the whole reason the
        strip is there.
        """
        config_path = _write_config(
            tmp_path,
            """\
            - path: "src/foo.py"
              rule_id: "B201"
              reason: >
                A long reason that happens to be
                wrapped across source lines.
            """,
        )

        assert _reason_issues(config_path) == []

    def test_only_the_offending_entry_is_flagged(self, tmp_path):
        config_path = _write_config(
            tmp_path,
            """\
            - path: "src/a.py"
              rule_id: "B101"
              reason: "Fine"
            - path: "src/b.py"
              rule_id: "B102"
              reason: |
                Broken
                across lines.
            - path: "src/c.py"
              rule_id: "B103"
              reason: "Also fine"
            """,
        )

        issues = _reason_issues(config_path)

        assert len(issues) == 1
        assert issues[0].path == "global_settings.suppressions[1]"

    def test_carriage_return_reason_is_flagged(self, tmp_path):
        """A CRLF file should not smuggle a newline past the check."""
        config_path = tmp_path / ".ash.yaml"
        config_path.write_bytes(
            b"project_name: crlf-probe\r\n"
            b"global_settings:\r\n"
            b"  suppressions:\r\n"
            b'    - path: "src/foo.py"\r\n'
            b'      rule_id: "B201"\r\n'
            b'      reason: "first\\nsecond"\r\n'
        )

        assert len(_reason_issues(config_path)) == 1


class TestMultilineReasonIsFixed:
    def test_fix_collapses_the_newline(self, tmp_path):
        config_path = _write_config(
            tmp_path,
            """\
            - path: "src/foo.py"
              rule_id: "B201"
              reason: |
                Multi-line reason
                with a newline.
            """,
        )

        fixed_content, fixed_issues = ConfigLinter.fix(config_path)

        assert any(
            issue.category == LintCategory.SUPPRESSION_MULTILINE_REASON
            for issue in fixed_issues
        )
        # The rendered reason must survive as one line of readable prose.
        assert "Multi-line reason with a newline." in fixed_content

    def test_fixed_config_lints_clean(self, tmp_path):
        """Applying the fix has to actually clear the warning.

        A fix that reports success without changing the loaded value would leave
        `ash config lint --fix` looping on the same warning forever.
        """
        config_path = _write_config(
            tmp_path,
            """\
            - path: "src/foo.py"
              rule_id: "B201"
              reason: |
                Multi-line reason
                with a newline.
            """,
        )

        fixed_content, _ = ConfigLinter.fix(config_path)
        config_path.write_text(fixed_content, encoding="utf-8")

        assert _reason_issues(config_path) == []


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("one\ntwo", "one two"),
        ("one\r\ntwo", "one two"),
        ("trailing newline\n", "trailing newline"),
        ("  padded \n out  ", "padded out"),
        ("leading\n\nnewlines", "leading newlines"),
        (None, ""),
        ("", ""),
    ],
)
def test_the_reporter_flattens_the_reason_on_render(raw, expected):
    """The linter warning is advisory; this is where the bug is actually fixed.

    The defect is in the reporter: it interpolates the reason into a single
    markdown bullet, so a newline ends that bullet. Fixing it here repairs the
    report for every config that already exists, without asking anyone to edit
    their file or run `--fix` (which re-dumps the config and drops its comments).

    Note this also handles the *leading*-newline case, which the linter's check
    deliberately does not flag: `reason.strip()` tolerates newlines at either end
    so the common trailing-newline-from-a-block-scalar does not warn, but a
    leading newline still breaks the bullet. Fixing it at the render point covers
    both without making the warning noisier.
    """
    from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
        _one_line,
    )

    assert _one_line(raw) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("one\ntwo", "one two"),
        ("one\r\ntwo", "one two"),
        ("trailing newline\n", "trailing newline"),
        ("  padded \n out  ", "padded out"),
        ("collapse\n\n\nruns", "collapse runs"),
        ("already fine", "already fine"),
    ],
)
def test_collapse_helper(raw, expected):
    """Pin the collapse rule directly, including the whitespace-run cases.

    A block scalar always ends with a newline, so "trailing newline\\n" is the
    common case rather than an edge case, and it must not become "x ".
    """
    assert ConfigLinter._collapse_reason_whitespace(raw) == expected
