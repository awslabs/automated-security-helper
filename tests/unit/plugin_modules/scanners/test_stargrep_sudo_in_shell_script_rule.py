# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The bundled stargrep rule ``sudo-in-shell-script``.

The rule's ``pattern-regex`` is read from the shipped YAML and run here with Python's
``re`` over fixture scripts; no tool is started. The regex uses only constructs
PCRE and Python's ``re`` read alike (an inline ``(?m)``, a negative lookahead, plain
character classes), so a match here is a match in semgrep and opengrep. The semgrep
run over the same fixtures is measured on a desk, not here.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List

import pytest
import yaml

from automated_security_helper.core.constants import ASH_ASSETS_DIR

pytestmark = pytest.mark.unit

RULE_ID = "sudo-in-shell-script"
RULES_FILE = Path(ASH_ASSETS_DIR) / "ash_stargrep_rules" / "appsec.yaml"
FIXTURES = Path(__file__).resolve().parents[3] / "test_data" / "stargrep"
CONVERTED = Path(__file__).resolve().parents[3] / "test_data" / "mcp_config_converted"


def _rule() -> dict:
    rules = yaml.safe_load(RULES_FILE.read_text(encoding="utf-8"))["rules"]
    found = [rule for rule in rules if rule["id"] == RULE_ID]
    assert len(found) == 1, [rule["id"] for rule in rules]
    return found[0]


def _flagged_lines(text: str) -> List[int]:
    pattern = re.compile(_rule()["pattern-regex"])
    return [text.count("\n", 0, hit.start()) + 1 for hit in pattern.finditer(text)]


def test_the_rule_is_one_error_level_regex_rule_for_shell_scripts():
    rule = _rule()
    assert rule["severity"] == "ERROR"
    assert rule["languages"] == ["none"]
    assert rule["paths"] == {"include": ["*.sh"]}
    assert "pattern-regex" in rule and "message" in rule


def test_every_must_flag_line_is_reported_and_no_other():
    text = (FIXTURES / "sudo_in_shell_script" / "must_flag.sh").read_text()
    assert _flagged_lines(text) == [4, 5, 6, 7, 8, 9, 10]


def test_the_must_not_flag_fixture_is_quiet():
    text = (FIXTURES / "sudo_in_shell_script" / "must_not_flag.sh").read_text()
    assert _flagged_lines(text) == []


@pytest.mark.parametrize(
    "script",
    sorted(CONVERTED.glob("*/violating/*/elevated.sh")),
    ids=lambda path: path.parents[2].name,
)
def test_the_converter_script_for_a_sudo_entry_is_flagged_on_the_exec_line(script):
    """The one line the converter writes for the entry, not its span comment."""
    text = script.read_text(encoding="utf-8")
    exec_line = [
        number
        for number, line in enumerate(text.splitlines(), start=1)
        if line.startswith("exec 'sudo'")
    ]
    assert len(exec_line) == 1, text
    assert _flagged_lines(text) == exec_line


@pytest.mark.parametrize(
    "script",
    sorted(CONVERTED.glob("*/*/*/*.sh")),
    ids=lambda path: f"{path.parents[2].name}-{path.parents[1].name}-{path.name}",
)
def test_a_converter_script_that_does_not_start_sudo_is_not_flagged(script):
    text = script.read_text(encoding="utf-8")
    if "exec 'sudo'" in text:
        pytest.skip("the sudo entry; flagged in the test above")
    assert _flagged_lines(text) == []


def test_there_are_ten_converter_formats_with_a_sudo_script():
    """Guards the parametrized tests above against matching nothing."""
    assert len(sorted(CONVERTED.glob("*/violating/*/elevated.sh"))) == 10
