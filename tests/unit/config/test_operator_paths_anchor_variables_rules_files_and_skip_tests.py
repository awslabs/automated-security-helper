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


def test_a_detect_secrets_file_entry_holding_a_dollar_is_anchored(tmp_path):
    """detect-secrets reads a ``file://<path>`` plugin entry as written, so a
    ``$`` in the path is a character of the file's name, and the relative path
    is anchored like a scanner's path option; left as written it would be read
    from the tool's working directory, the scanned tree. The ``::function``
    suffix rides along unchanged."""
    document = {
        "scanners": {
            "detect-secrets": {
                "options": {
                    "scan_settings": {
                        "plugins_used": [
                            {"name": "custom", "path": "file://plugins/$X/p.py::f"}
                        ]
                    }
                }
            }
        }
    }

    anchored = anchor_relative_paths(document, tmp_path)

    entry = anchored["scanners"]["detect-secrets"]["options"]["scan_settings"][
        "plugins_used"
    ][0]
    assert entry["path"] == f"file://{_anchored(tmp_path, 'plugins/$X/p.py')}::f"


def test_a_sandbox_read_path_holding_a_dollar_is_left_for_the_sandbox(tmp_path):
    document = {"sandbox": {"extra_read_paths": ["$HOME/ops"]}}

    anchored = anchor_relative_paths(document, tmp_path)

    assert anchored["sandbox"]["extra_read_paths"] == ["$HOME/ops"]


@pytest.mark.parametrize("scanner", ["semgrep", "opengrep"])
@pytest.mark.parametrize(
    "value", ["rules/custom.yaml", "./rules", "../shared/rules.yml"]
)
def test_a_missing_rules_file_spelled_as_a_path_is_anchored(tmp_path, scanner, value):
    """Nothing is at the value under the base; its spelling (a rules-file
    suffix, ``./``, ``../``) names a path all the same, so it is anchored, for
    opengrep's ``config`` as for semgrep's."""
    document = {"scanners": {scanner: {"options": {"config": value}}}}

    anchored = anchor_relative_paths(document, tmp_path)

    assert anchored["scanners"][scanner]["options"]["config"] == _anchored(
        tmp_path, value
    )


@pytest.mark.parametrize("scanner", ["semgrep", "opengrep"])
def test_a_registry_entry_is_left_as_written(tmp_path, scanner):
    document = {"scanners": {scanner: {"options": {"config": "p/ci"}}}}

    anchored = anchor_relative_paths(document, tmp_path)

    assert anchored["scanners"][scanner]["options"]["config"] == "p/ci"


@pytest.mark.parametrize("scanner", ["semgrep", "opengrep"])
def test_a_bare_name_is_anchored_only_when_a_file_is_there(tmp_path, scanner):
    """A bare name (no suffix, no ``./``) is spelled like a registry entry, so
    it is anchored only when something by that name sits under the base:
    ``myrules`` does here and is anchored; ``other-rules`` does not and stays as
    written, as ``p/ci`` beside it does."""
    (tmp_path / "myrules").mkdir()

    def anchored_config(value: str) -> str:
        document = {"scanners": {scanner: {"options": {"config": value}}}}
        return anchor_relative_paths(document, tmp_path)["scanners"][scanner][
            "options"
        ]["config"]

    assert anchored_config("myrules") == _anchored(tmp_path, "myrules")
    assert anchored_config("other-rules") == "other-rules"
    assert anchored_config("p/ci") == "p/ci"


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
