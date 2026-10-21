# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""--changed-files-only's help says it filters the findings, not the scan.

Every scanner scans every file, and the findings in files outside the diff are
dropped afterwards (ScanExecutionEngine._drop_findings_outside_changed_files). Help
that said the option limits the scan to the changed files sent operators looking
for a faster scan that does not exist. The reusable workflow's input says the same
(every file is still scanned).
"""

from __future__ import annotations

import pytest
import typer

from automated_security_helper.cli.main import app


@pytest.mark.parametrize("command", ["scan", None], ids=["ash scan", "ash"])
def test_the_help_says_every_file_is_still_scanned(command):
    root = typer.main.get_command(app)
    target = root if command is None else root.commands[command]
    (option,) = [p for p in target.params if "--changed-files-only" in p.opts]
    help_text = " ".join(option.help.split())

    assert "Report only findings in files changed" in help_text, help_text
    assert "still scan every file" in help_text, help_text
    assert "limit the scan" not in help_text.lower(), help_text
