# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash config update` refuses a `.json` config that uses `extends`, whatever
its indentation.

The rewrite refusal read every non-TOML file with the YAML loader. A JSON
file the YAML loader cannot read (one indented with tabs) made it answer
"nothing to refuse", and `update` then flattened the file's base into it. At
the base this test's update exits 0 and rewrites the file; at the tip it
exits 1 naming `extends` and leaves the file as written.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.cli.config import config_app

pytestmark = pytest.mark.unit

TAB_INDENTED_CHILD = '{\n\t"extends": "base.yaml",\n\t"project_name": "demo"\n}\n'


def test_update_refuses_a_tab_indented_json_file_that_extends_a_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    (tmp_path / "base.yaml").write_text("fail_on_findings: true\n", encoding="utf-8")
    child = tmp_path / ".ash.json"
    child.write_text(TAB_INDENTED_CHILD, encoding="utf-8")
    # The premise: JSON reads the file, the YAML loader refuses it.
    assert json.loads(TAB_INDENTED_CHILD)["extends"] == "base.yaml"
    with pytest.raises(yaml.YAMLError):
        yaml.safe_load(TAB_INDENTED_CHILD)

    result = CliRunner().invoke(
        config_app, ["update", str(child), "--set", "fail_on_findings=false"]
    )

    assert result.exit_code == 1, result.output
    assert "extends" in result.output
    assert child.read_text(encoding="utf-8") == TAB_INDENTED_CHILD
