# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash config lint --fix-unused` on a config that does not parse exits 3.

The lint pass marks a file it cannot load and goes on; with an
unused-suppressions report present, the fixer then read the file a second
time and the parser's error escaped as a traceback (exit 1) where the refusal
for such a file is exit 3. At the tip no fixer runs on a file the linter could
not load, and the refusal says the file does not parse.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.config import INVALID_CONFIG_EXIT_CODE, config_app

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "fix_flags",
    [["--fix-unused"], ["--fix", "--fix-unused"]],
    ids=["fix-unused", "fix-and-fix-unused"],
)
def test_fix_unused_on_a_file_that_does_not_parse_exits_3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fix_flags: list[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config_path = tmp_path / ".ash" / ".ash.yaml"
    config_path.parent.mkdir()
    unparsed = "global_settings: [unclosed\n"
    config_path.write_text(unparsed, encoding="utf-8")
    reports = tmp_path / ".ash" / "ash_output" / "reports"
    reports.mkdir(parents=True)
    (reports / "ash.unused-suppressions.json").write_text(
        json.dumps({"unused_suppressions": []}), encoding="utf-8"
    )

    result = CliRunner().invoke(
        config_app, ["lint", "--config", str(config_path), *fix_flags, "--yes"]
    )

    assert result.exit_code == INVALID_CONFIG_EXIT_CODE, result.output
    assert "does not parse" in result.output
    assert config_path.read_text(encoding="utf-8") == unparsed
