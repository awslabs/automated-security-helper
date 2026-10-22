# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``--cli-json-input`` refusal is one line, with the document's path whole.

Each refusal of the document names its file. Printed in a panel at the
console's width, 80 columns off a terminal, a path longer than a line was split
across lines, so a reader or a log search found no line holding it. Each
refusal is printed on one line.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

RUN_ASH_SCAN = "automated_security_helper.cli.scan.run_ash_scan"

#: Each refusal of a document, by the document that draws it: None for no file.
DOCUMENTS = {
    "cannot-read": None,
    "not-json": "{",
    "not-an-object": "[]",
    "unknown-key": json.dumps({"sauce_dir": "x"}),
    "two-keys-one-parameter": json.dumps({"source_dir": "a", "--source-dir": "b"}),
    "invalid-value": json.dumps({"output_formats": "sarif"}),
}


@pytest.mark.parametrize("kind", sorted(DOCUMENTS))
def test_the_refusal_is_one_line_holding_the_whole_path(tmp_path, kind):
    directory = tmp_path.joinpath("a-directory-name-long-enough" * 4)
    directory.mkdir()
    path = directory / f"{kind}.json"
    assert len(str(path)) > 120, "the control: the path is longer than a line"
    if DOCUMENTS[kind] is not None:
        path.write_text(DOCUMENTS[kind], encoding="utf-8")
    with patch(RUN_ASH_SCAN) as mock_run:
        result = CliRunner().invoke(app, ["scan", "--cli-json-input", str(path)])
    assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
    assert not mock_run.called
    lines = [line for line in result.output.splitlines() if "--cli-json-input:" in line]
    assert len(lines) == 1, result.output
    assert str(path) in lines[0], result.output
