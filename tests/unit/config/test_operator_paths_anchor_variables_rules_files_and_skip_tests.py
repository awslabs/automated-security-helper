# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Three anchoring rules of ``config/operator_paths.py``.

* A scanner's path option is read by the tool as written, so a ``$`` in it is a
  character of the file's name and the value is anchored like any other relative
  path; a ``sandbox.extra_read_paths`` entry holding ``$`` is left for the
  sandbox, which expands it.
* opengrep's and semgrep's ``config`` is anchored when a file is there, or when
  the value is spelled as a path (a rules-file suffix, ``./``); left as written,
  a missing file would be read from the tool's working directory, the scanned
  tree. A registry entry such as ``p/ci`` stays as written.
* A ``patch`` ``test`` operation sets nothing, so its value is not anchored: an
  anchored test of a path a base in another directory set would fail the load.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.config.operator_paths import (
    anchor_patch_operations,
    anchor_relative_paths,
)

pytestmark = pytest.mark.unit


def _anchored(base: Path, value: str) -> str:
    return os.path.normpath(os.path.join(os.fspath(base), value))


def test_a_scanner_path_option_holding_a_dollar_is_anchored(tmp_path):
    document = {"scanners": {"bandit": {"options": {"config_file": "cfg/$ENV/b.yaml"}}}}

    anchored = anchor_relative_paths(document, tmp_path)

    assert anchored["scanners"]["bandit"]["options"]["config_file"] == _anchored(
        tmp_path, "cfg/$ENV/b.yaml"
    )


def test_a_sandbox_read_path_holding_a_dollar_is_left_for_the_sandbox(tmp_path):
    document = {"sandbox": {"extra_read_paths": ["$HOME/ops"]}}

    anchored = anchor_relative_paths(document, tmp_path)

    assert anchored["sandbox"]["extra_read_paths"] == ["$HOME/ops"]


@pytest.mark.parametrize(
    "value", ["rules/custom.yaml", "./rules", "../shared/rules.yml"]
)
def test_a_missing_rules_file_spelled_as_a_path_is_anchored(tmp_path, value):
    document = {"scanners": {"semgrep": {"options": {"config": value}}}}

    anchored = anchor_relative_paths(document, tmp_path)

    assert anchored["scanners"]["semgrep"]["options"]["config"] == _anchored(
        tmp_path, value
    )


def test_a_registry_entry_is_left_as_written(tmp_path):
    document = {"scanners": {"semgrep": {"options": {"config": "p/ci"}}}}

    anchored = anchor_relative_paths(document, tmp_path)

    assert anchored["scanners"]["semgrep"]["options"]["config"] == "p/ci"


def test_a_root_pointer_operation_has_its_document_anchored(tmp_path):
    """A ``replace`` at the root pointer (the empty string) replaces the whole
    document; the loader accepts it, so the tool paths in its value are
    anchored as a file's own are."""
    ops = [
        {
            "op": "replace",
            "path": "",
            "value": {"scanners": {"bandit": {"options": {"config_file": "b.yaml"}}}},
        }
    ]

    anchored = anchor_patch_operations(ops, tmp_path)

    assert anchored[0]["value"]["scanners"]["bandit"]["options"][
        "config_file"
    ] == _anchored(tmp_path, "b.yaml")


def test_a_test_operation_keeps_its_value_while_a_replace_is_anchored(tmp_path):
    ops = [
        {
            "op": "test",
            "path": "/scanners/bandit/options/config_file",
            "value": "b.yaml",
        },
        {
            "op": "replace",
            "path": "/scanners/bandit/options/config_file",
            "value": "b.yaml",
        },
    ]

    anchored = anchor_patch_operations(ops, tmp_path)

    assert anchored[0]["value"] == "b.yaml"
    assert anchored[1]["value"] == _anchored(tmp_path, "b.yaml")
