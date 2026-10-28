# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash inspect sarif-fields`` prints the paths and names it found as text.

Why this exists
---------------
The command prints to a Rich console, which reads "[...]" as markup, and it quotes
what it found or was given: --sarif-dir, each SARIF file it reads, the error that
file raised, every file it writes under --output-dir, and each scanner's name, a
directory name from the analyzed tree, in its per-scanner table. Unescaped, a
"[/x]" in one would raise MarkupError out of the print and end the command in a
traceback; a "[bold]" would be taken as a style and dropped from the name. Each
is escaped once.
"""

from __future__ import annotations

import json
import re

from typer.testing import CliRunner

from automated_security_helper.cli.main import app

#: A closing tag with no opener, and a whole style tag around a word.
TEXT = "x[/x] [bold]y[/bold]"

#: A scanner directory's name: one path component, so no "/".
SCANNER = "s[bold]y"

SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "t"}},
            "results": [{"ruleId": "r", "message": {"text": "m"}}],
        }
    ],
}


def _plain(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _invoke(sarif_dir, output_dir):
    return CliRunner().invoke(
        app,
        [
            "inspect",
            "sarif-fields",
            "--sarif-dir",
            str(sarif_dir),
            "--output-dir",
            str(output_dir),
        ],
    )


def test_a_directory_with_no_sarif_files_is_named_as_text(tmp_path):
    missing = tmp_path / f"none-{TEXT}"

    result = _invoke(missing, tmp_path / "out")

    written = _plain(result.output)
    assert result.exit_code == 1, written
    assert "MarkupError" not in written, written
    assert written.count(f"No SARIF files found in {missing}") == 1, written


def test_the_files_read_and_written_and_the_scanner_are_named_as_text(tmp_path):
    scanner_dir = tmp_path / "in" / "scanners" / SCANNER
    scanner_dir.mkdir(parents=True)
    (scanner_dir / "a.sarif").write_text(json.dumps(SARIF), encoding="utf-8")
    (scanner_dir / "b.sarif").write_text("{", encoding="utf-8")
    output_dir = tmp_path / f"out-{TEXT}"

    result = _invoke(tmp_path / "in", output_dir)

    written = _plain(result.output)
    assert "MarkupError" not in written, written
    assert written.count(f"Analyzing {scanner_dir / 'a.sarif'}") == 1, written
    assert written.count(f"Error processing {scanner_dir / 'b.sarif'}: ") == 1, written
    # The two JSON files, the two CSV files and the HTML report.
    assert written.count(str(output_dir)) == 5, written
    # Twice in "Analyzing", once in the error, once in the per-scanner table.
    assert written.count(SCANNER) == 4, written
    assert "\\[" not in written, written
