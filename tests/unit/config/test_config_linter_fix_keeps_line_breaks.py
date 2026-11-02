# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ConfigLinter.fix`` gives the file's text back in the file's own line break.

Why this file exists
--------------------
``ash config lint --fix`` regenerates the config from the loaded data. The YAML
and JSON dumps write LF, and the schema comment was found by splitting the
file's text on LF alone, so a CRLF file came back with LF on every line but
the schema comment, which kept a stray CR. ``fix_unused_suppressions`` edits
the text and keeps the file's breaks; ``fix`` now does too: the content ends
every line with the first line break the file's text holds, and with LF when
it holds none.

The files are written as bytes, so the CRLF case runs on any platform (a
``write_text`` fixture is CRLF on Windows and LF elsewhere).
"""

import json
from pathlib import Path

import pytest
import yaml

from automated_security_helper.config.config_linter import ConfigLinter, LintCategory

pytestmark = pytest.mark.unit

SCHEMA_COMMENT = (
    "# yaml-language-server: $schema=https://example.invalid/AshConfig.json"
)


def _write_bytes(config_path: Path, text_with_lf: str, newline: str) -> None:
    config_path.write_bytes(text_with_lf.replace("\n", newline).encode("utf-8"))


@pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
def test_a_fixed_file_keeps_the_line_break_it_was_written_with(tmp_path, newline):
    """Red at the base for the CRLF case: the content was LF throughout except
    the schema comment, which carried a stray CR (the text was split on LF
    only), so the result held a bare LF after the comment's CRLF and a CR the
    file never had. The LF case is the control: it was and stays unchanged."""
    config_path = tmp_path / "ash.yaml"
    _write_bytes(
        config_path,
        f"{SCHEMA_COMMENT}\nproject_name: demo\nscanners:\n  bandit:\n"
        "    name: bandit\n",
        newline,
    )
    issues = [
        issue
        for issue in ConfigLinter.lint(config_path).fixable_issues
        if issue.category == LintCategory.INTERNAL_FIELD
    ]
    # The control: lint raised the fixable issue the fix below applies.
    assert [issue.path for issue in issues] == ["scanners.bandit.name"]

    fixed, fixed_issues = ConfigLinter.fix(config_path, issues)

    assert [issue.path for issue in fixed_issues] == ["scanners.bandit.name"]
    # Every line break of the result is the file's own.
    leftover = fixed.replace(newline, "")
    assert "\n" not in leftover and "\r" not in leftover, repr(fixed)
    lines = fixed.split(newline)
    assert lines[0] == SCHEMA_COMMENT, repr(lines[0])
    assert fixed.endswith(newline), repr(fixed[-20:])
    data = yaml.safe_load(fixed)
    assert data["project_name"] == "demo"
    assert "name" not in data["scanners"]["bandit"]


def test_a_file_with_no_line_break_is_fixed_with_lf(tmp_path):
    """The default when the file's text holds no break to follow."""
    config_path = tmp_path / "ash.yaml"
    config_path.write_bytes(b"project_name: demo")

    fixed, _fixed_issues = ConfigLinter.fix(config_path, [])

    assert "\r" not in fixed, repr(fixed)
    assert fixed.endswith("\n"), repr(fixed)
    assert yaml.safe_load(fixed) == {"project_name": "demo"}


@pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
def test_a_fixed_json_file_keeps_the_line_break_it_was_written_with(tmp_path, newline):
    """Red at the base for the CRLF case: the JSON dump was returned as it is,
    LF throughout."""
    config_path = tmp_path / "ash.json"
    raw = '{"project_name": "demo"}' + newline

    fixed = ConfigLinter._generate_config_content(
        config_path, raw, {"project_name": "demo"}
    )

    assert fixed == newline.join(["{", '  "project_name": "demo"', "}", ""]), repr(
        fixed
    )
    assert json.loads(fixed) == {"project_name": "demo"}
