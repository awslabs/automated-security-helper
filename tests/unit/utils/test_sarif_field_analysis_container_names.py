# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One field has one name, whether its container is empty or filled.

An empty container was recorded under its own path (``...locations``) while a
non-empty one was recorded only through its children
(``...locations[].physicalLocation...``). A scanner result with an empty
``locations`` list whose aggregate filled it, or the reverse, was reported as
missing a field the aggregate had kept, and the run exited 1.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import typer

from automated_security_helper.utils.sarif_field_analysis import (
    analyze_sarif_fields,
    flatten_sarif_results,
)

pytestmark = pytest.mark.unit

RESULT = "runs[].results[]"
LOCATION = {"physicalLocation": {"artifactLocation": {"uri": "a.py"}}}


def _fields(result: dict) -> set[str]:
    included, _ = flatten_sarif_results({"runs": [{"results": [result]}]})
    return set(included)


def test_an_empty_and_a_filled_container_share_one_name():
    empty = _fields({"ruleId": "R1", "locations": []})
    filled = _fields({"ruleId": "R1", "locations": [LOCATION]})

    assert f"{RESULT}.locations" in empty
    assert f"{RESULT}.locations" in filled
    # The filled form also records what the container holds.
    assert f"{RESULT}.locations[].physicalLocation.artifactLocation.uri" in filled


def test_a_container_of_empty_containers_is_still_a_field():
    """``[{}]`` and ``[[]]`` hold nothing to walk, and recorded nothing at all."""
    fields = _fields({"fixes": [{}], "codeFlows": [[]], "message": {}})

    assert {f"{RESULT}.fixes", f"{RESULT}.codeFlows", f"{RESULT}.message"} <= fields


def test_a_list_of_scalars_is_recorded_as_the_list_and_as_its_elements():
    fields = _fields({"tags": ["a", "b"]})

    assert {f"{RESULT}.tags", f"{RESULT}.tags[]"} <= fields


def test_a_nested_object_records_itself_and_its_leaves():
    fields = _fields({"message": {"text": "x"}})

    assert {f"{RESULT}.message", f"{RESULT}.message.text"} <= fields


def test_an_aggregate_that_filled_an_empty_container_kept_the_field(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("COLUMNS", "200")
    sarif_dir: Path = tmp_path / "ash_output"
    (sarif_dir / "reports").mkdir(parents=True)
    (sarif_dir / "scanners" / "bandit").mkdir(parents=True)
    (sarif_dir / "scanners" / "bandit" / "bandit.sarif").write_text(
        json.dumps({"runs": [{"results": [{"ruleId": "R1", "locations": []}]}]}),
        encoding="utf-8",
    )
    (sarif_dir / "reports" / "ash.sarif").write_text(
        json.dumps(
            {"runs": [{"results": [{"ruleId": "R1", "locations": [LOCATION]}]}]}
        ),
        encoding="utf-8",
    )

    exit_code = 0
    try:
        analyze_sarif_fields(sarif_dir=str(sarif_dir), output_dir=str(tmp_path / "out"))
    except typer.Exit as raised:
        exit_code = raised.exit_code

    out = re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().out)
    # The empty ``locations`` was reported as unexpectedly missing from the
    # aggregate, which had it filled.
    assert "unexpectedly missing" not in out
    assert exit_code == 0
