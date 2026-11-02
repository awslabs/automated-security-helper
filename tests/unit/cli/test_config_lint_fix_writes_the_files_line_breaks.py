# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash config lint --fix`` writes the fixed text as it was given, line breaks included.

Why this file exists
--------------------
``ConfigLinter.fix`` gives the config's text back ending every line with the
file's own line break (CRLF for a CRLF file). ``_apply_fixes`` wrote that text
through ``_write_config_text``, a text-mode write, and text mode turns each
"\\n" it is given into the platform's line separator. On Windows a CRLF file's
"\\r\\n" therefore became "\\r\\r\\n" on every line. The unused-suppression fixer
already writes bytes for the same reason (``_apply_unused_fixes``); the fixer
for every other issue now does too.

The Windows write is simulated here (the text writer is replaced with one that
turns each "\\n" into "\\r\\n", as the platform's text mode does), so the failure
reproduces on any platform. The files are written as bytes for the same reason.
"""

from pathlib import Path

import pytest

from automated_security_helper.cli import config as config_cli
from automated_security_helper.config.config_linter import ConfigLinter, LintCategory

pytestmark = pytest.mark.unit

SCHEMA_COMMENT = (
    "# yaml-language-server: $schema=https://example.invalid/AshConfig.json"
)


def _text_mode_as_on_windows(config_path: Path, text: str) -> None:
    """What a text-mode write does on Windows: each "\\n" becomes "\\r\\n"."""
    Path(config_path).write_bytes(text.replace("\n", "\r\n").encode("utf-8"))


@pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
def test_fix_writes_a_file_with_the_line_break_it_was_written_with(
    tmp_path, monkeypatch, newline
):
    """Red before the change on the simulated Windows write: the fixed text was
    handed to the text writer, which doubled the CR of every CRLF line (and
    gave an LF file CRLF). Green once the bytes are written as they are."""
    monkeypatch.setattr(config_cli, "_write_config_text", _text_mode_as_on_windows)
    config_path = tmp_path / "ash.yaml"
    config_path.write_bytes(
        (
            f"{SCHEMA_COMMENT}\nproject_name: demo\nscanners:\n  bandit:\n"
            "    name: bandit\n"
        )
        .replace("\n", newline)
        .encode("utf-8")
    )
    fixable = [
        issue
        for issue in ConfigLinter.lint(config_path).fixable_issues
        if issue.category == LintCategory.INTERNAL_FIELD
    ]
    # The control: lint raised the fixable issue the fix below applies.
    assert [issue.path for issue in fixable] == ["scanners.bandit.name"]

    written = config_cli._apply_fixes(
        config_path, fixable, non_interactive=True, color=False
    )

    assert written is True
    data = config_path.read_bytes()
    leftover = data.replace(newline.encode("ascii"), b"")
    assert b"\n" not in leftover and b"\r" not in leftover, repr(data)
    assert data.split(newline.encode("ascii"))[0] == SCHEMA_COMMENT.encode("utf-8")
    assert data.endswith(newline.encode("ascii")), repr(data[-20:])
    assert b"    name: bandit" not in data
    assert b"project_name: demo" in data
