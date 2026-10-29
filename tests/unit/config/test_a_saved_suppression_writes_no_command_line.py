# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No line of a suppression ``add_suppression_to_config`` saves is a CI workflow
command.

A suppression names a finding's path, which comes from the scanned tree, and a
reason. A CI runner reads a line of its log that starts, after its indentation,
with ``::`` (GitHub Actions) or ``##`` (Azure Pipelines' ``##[`` and ``##vso[``,
TeamCity's ``##teamcity[``) as a command, and ``yaml.safe_dump`` writes a value
holding a line break as a block of lines. The suppression is written through
ash_config's ``_ConfigDumper`` both ways: as lines inserted into the file, and as
a whole rewrite of a file it cannot edit as text.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from automated_security_helper.config.ash_config import (
    add_suppression_to_config,
    load_yaml_config,
)
from automated_security_helper.models.core import AshSuppression

pytestmark = pytest.mark.unit

#: Values a suppression can hold, each with a line that is a CI command unless
#: the writer writes it on one line.
VALUES = {
    "newline-add-mask": "x\n::add-mask::secret-a",
    "newline-vso": "x\n##vso[task.setvariable variable=x]secret-b",
    "folded-after-an-escape": "A" * 68 + "\n::add-mask::secret-c",
}

CASES = [pytest.param(value, id=name) for name, value in VALUES.items()]

#: A config add_suppression_to_config edits as text: with a suppressions list,
#: with a global_settings block and no list, and with neither; one it
#: rewrites whole, an inline global_settings mapping; and no file at all
#: (``None``), which the save creates whole.
SHAPES = {
    "into-a-list": "global_settings:\n  suppressions:\n  - rule_id: R0\n    path: b.py\n    reason: kept\n",
    "into-global-settings": "global_settings:\n  severity_threshold: MEDIUM\n",
    "appended": "fail_on_findings: true\n",
    "rewritten": "global_settings: {severity_threshold: MEDIUM}\n",
    "new-file": None,
}


def _command_lines(text: str) -> List[str]:
    return [
        line for line in text.splitlines() if line.lstrip().startswith(("::", "##"))
    ]


def _read(text: str) -> Dict[str, Any]:
    """What a scan reads from ``text``."""
    return load_yaml_config(text) or {}


def _config_file(tmp_path: Path, rest: str | None) -> Path:
    """The config to save into: *rest* appended to a one-key head, or, for
    ``None`` (the new-file shape), a path with no file behind it."""
    path = tmp_path / ".ash" / ".ash.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    if rest is not None:
        path.write_text(f"project_name: {json.dumps('demo')}\n{rest}", "utf-8")
    return path


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("value", CASES)
def test_add_suppression_to_config(tmp_path, value, shape):
    path = _config_file(tmp_path, SHAPES[shape])

    written_at_all = add_suppression_to_config(
        path, AshSuppression(rule_id="R1", path=value, reason=value)
    )

    assert written_at_all is True
    written = path.read_text(encoding="utf-8")
    assert _command_lines(written) == [], _command_lines(written)
    added = _read(written)["global_settings"]["suppressions"][-1]
    assert (added["rule_id"], added["path"], added["reason"]) == ("R1", value, value)


#: One command of each form a runner reads.
FORMS = [
    "::add-mask::secret",
    "##[group]x",
    "##vso[task.setvariable variable=x]y",
    "##teamcity[message text='x']",
]

#: Where in a value the command sits: first, after whitespace, or after a
#: character YAML writes as an escape.
PLACES = ["", "a ", "a\t", "x\n", "x\r", "x\a", "x\x85", "${X}\n"]


@pytest.mark.parametrize("form", FORMS)
def test_the_config_dumper_writes_no_command_line_and_reads_back(form):
    from automated_security_helper.config.ash_config import _ConfigDumper

    for place in PLACES:
        for length in (0, 40, 68, 75, 120):
            value = "A" * length + place + form + " and more"
            for data in ({"name": value}, {value: "x"}, [value], {"a": {"b": [value]}}):
                text = yaml.dump(
                    data,
                    Dumper=_ConfigDumper,
                    default_flow_style=False,
                    sort_keys=False,
                )
                assert _command_lines(text) == [], text
                assert yaml.safe_load(text) == data, text


def test_the_config_dumper_writes_other_values_as_safe_dump_does():
    """A value with no command mark is written as ``yaml.safe_dump`` writes it."""
    from automated_security_helper.config.ash_config import _ConfigDumper

    data = [
        {
            "rule_id": "R1",
            "path": "tool_name::bandit",
            "reason": "no findings\nin the scan",
            "inside": "a##vso[x]b",
        }
    ]

    assert yaml.dump(
        data, Dumper=_ConfigDumper, default_flow_style=False, sort_keys=False
    ) == yaml.safe_dump(data, default_flow_style=False, sort_keys=False)
