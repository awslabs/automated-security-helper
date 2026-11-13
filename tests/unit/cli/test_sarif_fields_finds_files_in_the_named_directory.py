# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash inspect sarif-fields`` reads the SARIF files in the directory it is given.

Why this exists
---------------
The command finds its SARIF files with glob patterns built by joining --sarif-dir
and "reports/*.sarif" (and "scanners/**/*.sarif"); unescaped, the directory's own
name would be read as a pattern too. A directory named with "[ab]" would be read
as a character class: its own files not found, and a sibling's, "sa" or "sb",
found instead. One named with "*" would match every sibling it prefixed. The
directory part is escaped; the pattern part is still a glob.
"""

from __future__ import annotations

import json
import os

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

#: A directory named with "*" cannot be made on Windows, where "*" is reserved in
#: a file name, so the star case has no directory to read there; the glob-escape it
#: checks is the same code path the character-class case runs on every OS.
_NOT_A_WINDOWS_NAME = pytest.mark.skipif(
    os.name == "nt", reason='"*" is not allowed in a Windows file name'
)

SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "t"}},
            "results": [{"ruleId": "r", "message": {"text": "m"}}],
        }
    ],
}


def _plant(directory, stem):
    reports = directory / "reports"
    reports.mkdir(parents=True)
    (reports / f"{stem}.sarif").write_text(json.dumps(SARIF), encoding="utf-8")


def _plant_scanner(directory, stem):
    """A per-scanner file, as a scan writes them: scanners/<scanner>/<file>.sarif."""
    scanner = directory / "scanners" / stem
    scanner.mkdir(parents=True)
    (scanner / f"{stem}.sarif").write_text(json.dumps(SARIF), encoding="utf-8")


@pytest.mark.parametrize(
    "name, sibling",
    [
        pytest.param("plain", "plainer", id="control"),
        pytest.param("s[ab]", "sa", id="character-class"),
        pytest.param("d*", "dz", id="star", marks=_NOT_A_WINDOWS_NAME),
    ],
)
def test_only_the_named_directorys_files_are_read(tmp_path, name, sibling):
    _plant(tmp_path / name, "mine")
    _plant(tmp_path / sibling, "theirs")
    output = tmp_path / "out"

    result = CliRunner().invoke(
        app,
        [
            "inspect",
            "sarif-fields",
            "--sarif-dir",
            str(tmp_path / name),
            "--output-dir",
            str(output),
        ],
    )

    assert "Found 1 SARIF files" in result.output, result.output
    fields = json.loads((output / "sarif_fields.json").read_text(encoding="utf-8"))
    scanners = {scanner for found in fields.values() for scanner in found}
    assert scanners == {"mine"}, scanners


@pytest.mark.parametrize(
    "name, sibling",
    [
        pytest.param("plain", "plainer", id="control"),
        pytest.param("s[ab]", "sa", id="character-class"),
        pytest.param("d*", "dz", id="star", marks=_NOT_A_WINDOWS_NAME),
    ],
)
def test_only_the_named_directorys_scanner_files_are_read(tmp_path, name, sibling):
    """The scanners/ pattern reads the named directory too: it is a second
    pattern of its own, so an escape on the reports/ one alone leaves a
    directory named with "[ab]" or "*" reading a sibling's scanner files."""
    _plant_scanner(tmp_path / name, "mine")
    _plant_scanner(tmp_path / sibling, "theirs")
    output = tmp_path / "out"

    result = CliRunner().invoke(
        app,
        [
            "inspect",
            "sarif-fields",
            "--sarif-dir",
            str(tmp_path / name),
            "--output-dir",
            str(output),
        ],
    )

    assert "Found 1 SARIF files" in result.output, result.output
    fields = json.loads((output / "sarif_fields.json").read_text(encoding="utf-8"))
    scanners = {scanner for found in fields.values() for scanner in found}
    assert scanners == {"mine"}, scanners
