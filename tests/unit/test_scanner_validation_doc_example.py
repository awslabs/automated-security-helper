# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The "Validation Summary in Metadata" example matches what the scan phase writes.

docs/content/developer-guide/scanner-validation-system.md shows the
``metadata.validation_summary`` a scan leaves behind. The example had drifted from
scan_phase.py: two of its five entries are written by nothing, the task entry was named
``task_queue_validation`` where the code writes ``scanner_tasks_validation``, the two
completion entries listed fields the code does not write, and it showed a missing
scanner setting ``has_issues``, which counts only discrepancies and errors.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from automated_security_helper.models.scanner_validation import ValidationCheckpoint

REPO_ROOT = Path(__file__).resolve().parents[2]
DOC = REPO_ROOT / "docs/content/developer-guide/scanner-validation-system.md"
SCAN_PHASE = REPO_ROOT / "automated_security_helper/core/phases/scan_phase.py"
HEADING = "### Validation Summary in Metadata"


def _documented_summary() -> dict:
    text = DOC.read_text(encoding="utf-8")
    assert HEADING in text, f"{DOC.name} no longer has the section {HEADING!r}"
    section = text.split(HEADING, 1)[1]
    match = re.search(r"```json\n(.*?)\n```", section, re.DOTALL)
    assert match, f"no JSON example under {HEADING!r}"
    return json.loads(match.group(1))["validation_summary"]


def _is_validation_summary(node: ast.AST) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == "validation_summary"


def _written_summary(source: str = "") -> dict:
    """``{entry: [field, ...]}`` from each ``...validation_summary["entry"] = {...}``.

    Reads scan_phase.py unless given ``source``. Any other way of writing an entry
    fails the reader rather than going unread: a value that is not a dict literal, a
    key that is not a string literal, an augmented assignment, or ``update`` or
    ``setdefault`` on the summary.
    """
    text = source or SCAN_PHASE.read_text(encoding="utf-8")
    written, unreadable = {}, []
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and _is_validation_summary(func.value)
                and func.attr in ("update", "setdefault", "__setitem__")
            ):
                unreadable.append(ast.unparse(node))
            continue
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            targets, value = [node.target], None
        else:
            continue
        for target in targets:
            if not (
                isinstance(target, ast.Subscript)
                and _is_validation_summary(target.value)
            ):
                continue
            key = target.slice
            if (
                not isinstance(key, ast.Constant)
                or not isinstance(key.value, str)
                or not isinstance(value, ast.Dict)
                or not all(isinstance(k, ast.Constant) for k in value.keys)
            ):
                unreadable.append(ast.unparse(node))
                continue
            written[key.value] = [k.value for k in value.keys]
    where = "the given source" if source else SCAN_PHASE.name
    assert not unreadable, (
        f"this test cannot read these validation_summary writes in {where}; write each "
        f"entry as a dict literal, or teach _written_summary the new shape: {unreadable}"
    )
    assert written, f"found no validation_summary entries in {where}"
    return written


@pytest.mark.parametrize(
    "source",
    [
        pytest.param('r.validation_summary["built"] = build()', id="from-a-call"),
        pytest.param('r.validation_summary[name] = {"a": 1}', id="computed-key"),
        pytest.param('r.validation_summary.update(new={"a": 1})', id="update"),
        pytest.param('r.validation_summary.setdefault("new", {})', id="setdefault"),
        pytest.param('r.validation_summary["x"] |= {"a": 1}', id="augmented"),
    ],
)
def test_the_reader_refuses_an_entry_it_cannot_read(source):
    """An entry written in any other shape would be missed, and the example not checked."""
    with pytest.raises(AssertionError, match="cannot read"):
        _written_summary(source)


def test_the_reader_reads_a_dict_literal_entry():
    source = 'r.validation_summary["entry"] = {"timestamp": t, "has_issues": h}'
    assert _written_summary(source) == {"entry": ["timestamp", "has_issues"]}


def test_the_example_has_the_entries_the_scan_phase_writes():
    assert sorted(_documented_summary()) == sorted(_written_summary())


def test_each_entry_has_the_fields_the_scan_phase_writes():
    documented, written = _documented_summary(), _written_summary()
    mismatched = {
        entry: {"documented": sorted(documented[entry]), "written": sorted(fields)}
        for entry, fields in written.items()
        if entry in documented and sorted(documented[entry]) != sorted(fields)
    }
    assert not mismatched, mismatched


def test_a_missing_scanner_alone_is_not_an_issue_and_the_example_says_so():
    checkpoint = ValidationCheckpoint(
        checkpoint_name="task_queue_validation",
        expected_scanners=["bandit", "semgrep"],
        actual_scanners=["bandit"],
    )
    assert checkpoint.get_missing_scanners() == ["semgrep"]
    assert checkpoint.has_issues() is False

    entry = _documented_summary()["scanner_tasks_validation"]
    assert entry["missing_count"] > 0, "the example no longer shows a missing scanner"
    assert entry["has_issues"] is False, entry


def test_the_example_counts_add_up():
    """One scanner without a task: queued ones are what execution expects."""
    summary = _documented_summary()
    tasks = summary["scanner_tasks_validation"]
    execution = summary["execution_completion_validation"]
    completeness = summary["result_completeness_validation"]
    assert tasks["expected_count"] - tasks["actual_count"] == tasks["missing_count"]
    assert execution["expected_count"] == tasks["actual_count"]
    assert completeness["expected_count"] == tasks["expected_count"]
    assert completeness["missing_count"] == tasks["missing_count"]
    # The completeness check records a discrepancy for each scanner it adds.
    assert completeness["has_issues"] is (completeness["missing_count"] > 0)
