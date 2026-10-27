# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No workflow file repeats a key inside one mapping.

Why this file exists
--------------------
GitHub rejects a workflow file whose mapping holds the same key twice. PyYAML's
``safe_load`` does not: it keeps the last value without a word, so a test that loads
a workflow with it reads a file GitHub would never run.

run-ash-security-scan.yml declared ``on.workflow_call.outputs`` twice for that
reason. Two branches each added one block, the merge kept both, and every test that
read ``outputs["artifact-id"]`` through ``safe_load`` still passed.

This loads every workflow with a loader that raises on a repeated key. Two controls
keep it honest: a planted repeat must raise, and the same key under two different
parents must not, so a loader that stopped checking turns a test red instead of
passing every file.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
SCAN_WORKFLOW = WORKFLOWS / "run-ash-security-scan.yml"

_MERGE_TAG = "tag:yaml.org,2002:merge"


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that raises on a key repeated inside one mapping."""


def _construct_unique_mapping(loader, node, deep=False):
    seen: dict = {}
    for key_node, _value_node in node.value:
        if key_node.tag == _MERGE_TAG:
            continue
        key = loader.construct_object(key_node, deep=True)
        try:
            hash(key)
        except TypeError:
            # SafeLoader's own construct_mapping refuses an unhashable key.
            continue
        line = key_node.start_mark.line + 1
        if key in seen:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found a duplicate key {key!r} (lines {seen[key]} and {line})",
                key_node.start_mark,
            )
        seen[key] = line
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _load_unique(text: str):
    loader = _UniqueKeyLoader(text)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def _workflow_files() -> list[Path]:
    return sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])


def test_the_workflow_directory_was_read():
    # A zero count would let the parametrized test below pass over nothing.
    files = _workflow_files()
    assert SCAN_WORKFLOW in files, [path.name for path in files]
    assert len(files) > 1, [path.name for path in files]


@pytest.mark.parametrize("path", _workflow_files(), ids=lambda path: path.name)
def test_a_workflow_repeats_no_key(path):
    document = _load_unique(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict), path.name
    assert document.get("jobs"), path.name


def test_control_a_repeated_key_is_refused():
    planted = "parent:\n  outputs:\n    a: 1\n  outputs:\n    b: 2\n"
    with pytest.raises(yaml.constructor.ConstructorError, match="duplicate key"):
        _load_unique(planted)


def test_control_the_same_key_under_two_parents_is_accepted():
    sibling = "left:\n  outputs:\n    a: 1\nright:\n  outputs:\n    a: 2\n"
    document = _load_unique(sibling)
    assert document["left"]["outputs"] == {"a": 1}
    assert document["right"]["outputs"] == {"a": 2}


def test_the_scan_workflow_declares_its_artifact_id_output_once():
    document = _load_unique(SCAN_WORKFLOW.read_text(encoding="utf-8"))
    # PyYAML reads the bare key `on` as the boolean True (YAML 1.1).
    triggers = document.get("on", document.get(True))
    outputs = triggers["workflow_call"]["outputs"]
    assert list(outputs) == ["artifact-id"], list(outputs)
    assert outputs["artifact-id"]["value"] == "${{ jobs.ash.outputs.artifact-id }}"
