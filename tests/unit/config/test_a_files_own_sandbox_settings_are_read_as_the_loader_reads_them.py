# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file's own sandbox settings are read as the config loader reads them.

``_own_sandbox_settings`` gives the ``sandbox`` section an operator's root config
writes itself, without what its ``extends`` bases give it. The loader reads the
same file in three ways a raw parse does not, and the section has to agree with
the loader on each:

- the file's own ``patch`` operations that set or clear ``sandbox.mode`` count,
  because the merge applies them last, so the mode the file ends with is the mode
  it chose;
- a relative ``sandbox.extra_read_paths`` entry is made absolute against the
  file's directory, as the merged chain has it;
- an unquoted ``mode: off`` is the mode ``"off"`` (YAML reads it as a boolean),
  so the section still validates and the file keeps the grants it writes.

A ``patch`` operation that adds a grant (a pointer under ``/sandbox`` other than
``/sandbox/mode``, or a key other than ``mode`` in a rewritten section) is not
read: the own section keeps the grants the file wrote directly. An operation that
removes or rewrites a setting the file wrote is read, and takes that setting out of
the section; the cases for those operations are in
``test_a_grant_list_the_files_own_patch_rewrites_is_read_as_patched``.

The settings come from the document the chain load already read when the caller
carries it (``documents``, by resolved path); the file is read again only by a
caller that carries none, and a carried mapping that lacks the file gives nothing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

import pytest
import yaml

from automated_security_helper.config.ash_config import SandboxConfig
from automated_security_helper.config.resolve_config import (
    _own_sandbox_read,
    _own_sandbox_settings,
)
from automated_security_helper.utils.sandbox.policy import DEFAULT_ENVIRONMENT

pytestmark = pytest.mark.unit


def _config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "cfg" / "root.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _config_of(tmp_path: Path, document: Dict[str, Any]) -> Path:
    return _config(tmp_path, yaml.safe_dump(document, sort_keys=False))


def _op(op: str, path: str, value: Any = None) -> Dict[str, Any]:
    operation: Dict[str, Any] = {"op": op, "path": path}
    if op != "remove":
        operation["value"] = value
    return operation


#: (id, the section the file writes directly, its own patch operations, the
#: section it ends with).
_MODE_CASES = [
    pytest.param(
        {"mode": "bwrap"},
        [_op("add", "/sandbox", {"mode": "off"})],
        {"mode": "off"},
        id="a-rewritten-section-replaces-the-written-mode",
    ),
    pytest.param(
        {"mode": "bwrap"},
        [_op("replace", "/sandbox/mode", "auto")],
        {"mode": "auto"},
        id="a-replaced-mode",
    ),
    pytest.param(
        None,
        [_op("add", "/sandbox/mode", "firejail")],
        {"mode": "firejail"},
        id="an-added-mode-with-no-written-section",
    ),
    pytest.param(
        {"mode": "bwrap"},
        [
            _op("add", "/sandbox/mode", "firejail"),
            _op("replace", "/sandbox/mode", "landlock"),
        ],
        {"mode": "landlock"},
        id="operations-apply-in-order",
    ),
    pytest.param(
        {"mode": "bwrap", "extra_read_paths": ["/opt/a"]},
        [_op("replace", "/sandbox/mode", "off")],
        {"mode": "off", "extra_read_paths": ["/opt/a"]},
        id="the-other-written-keys-stay",
    ),
    pytest.param(
        {"mode": "bwrap"},
        [_op("remove", "/sandbox/mode")],
        {},
        id="a-removed-mode",
    ),
    pytest.param(
        {"mode": "bwrap"},
        [_op("remove", "/sandbox")],
        {},
        id="a-removed-section",
    ),
    pytest.param(
        {"mode": "bwrap"},
        [_op("add", "/sandbox", {})],
        {},
        id="a-section-rewritten-without-a-mode",
    ),
    pytest.param(
        {"mode": "bwrap"},
        [_op("add", "", {"project_name": "rewritten"})],
        {},
        id="a-document-rewritten-without-a-section",
    ),
    pytest.param(
        {"mode": "bwrap"},
        [_op("add", "", {"sandbox": {"mode": "auto"}})],
        {"mode": "auto"},
        id="a-document-rewritten-with-a-mode",
    ),
    pytest.param(
        {"mode": "bwrap"},
        [_op("test", "/sandbox/mode", "bwrap")],
        {"mode": "bwrap"},
        id="a-test-sets-nothing",
    ),
    pytest.param(
        {"mode": "bwrap"},
        [{"op": "move", "from": "/elsewhere", "path": "/sandbox/mode"}],
        {"mode": "bwrap"},
        id="a-move-sets-nothing",
    ),
]


@pytest.mark.parametrize("written, operations, expected", _MODE_CASES)
def test_the_mode_a_file_ends_with_is_the_mode_it_wrote(
    tmp_path, written, operations, expected
):
    document: Dict[str, Any] = {}
    if written is not None:
        document["sandbox"] = written
    document["patch"] = operations
    root = _config_of(tmp_path, document)

    assert _own_sandbox_settings(root) == expected


def test_a_relative_extra_read_path_is_anchored_at_the_files_directory(tmp_path):
    root = _config(
        tmp_path,
        "sandbox:\n  extra_read_paths:\n    - grants/extra\n    - /opt/absolute\n",
    )

    anchored = str(tmp_path.resolve() / "cfg" / "grants" / "extra")
    assert _own_sandbox_settings(root) == {
        "extra_read_paths": [anchored, "/opt/absolute"]
    }


def test_an_unquoted_mode_off_is_the_mode_off(tmp_path):
    root = _config(
        tmp_path, "sandbox:\n  mode: off\n  extra_read_paths:\n    - /opt/keep\n"
    )

    own = _own_sandbox_settings(root)

    assert own == {"mode": "off", "extra_read_paths": ["/opt/keep"]}
    SandboxConfig.model_validate(own, strict=True)


def test_a_patch_that_adds_a_grant_beside_the_mode_adds_nothing(tmp_path):
    root = _config_of(
        tmp_path,
        {
            "sandbox": {"extra_read_paths": ["/opt/a"]},
            "patch": [
                _op("add", "/sandbox/extra_read_paths/0", "/opt/b"),
                _op("add", "/sandbox/network_scanners", ["grype"]),
            ],
        },
    )

    assert _own_sandbox_settings(root) == {"extra_read_paths": ["/opt/a"]}


def test_the_grants_a_rewritten_section_carries_are_not_adopted(tmp_path):
    root = _config_of(
        tmp_path,
        {
            "sandbox": {"mode": "bwrap"},
            "patch": [
                _op(
                    "add",
                    "/sandbox",
                    {"mode": "off", "extra_read_paths": ["/opt/c"]},
                )
            ],
        },
    )

    assert _own_sandbox_settings(root) == {"mode": "off"}


@pytest.mark.parametrize(
    "written, operations, limits",
    [
        pytest.param({"mode": "bwrap"}, [], {}, id="no-patch-no-limit"),
        pytest.param(
            {"mode": "bwrap"},
            [
                _op(
                    "add",
                    "/sandbox",
                    {"mode": "off", "extra_read_paths": ["/opt/c"]},
                )
            ],
            {
                "extra_read_paths": ["/opt/c"],
                # The rewrite carries no other grant list, so the file's config ends
                # with the model's default there: the empty list for the two scanner
                # lists, the proxy and CA names for the environment list.
                "read_path_scanners": [],
                "env_scanners": [],
                "environment": list(DEFAULT_ENVIRONMENT),
            },
            id="a-rewritten-section-that-carries-a-list",
        ),
        pytest.param(
            {"mode": "bwrap"},
            [_op("add", "/sandbox/network_scanners", ["grype"])],
            {"network_scanners": ["grype"]},
            id="an-added-network-list",
        ),
        pytest.param(
            {"mode": "bwrap", "env_scanners": None},
            [_op("replace", "/sandbox/env_scanners", ["semgrep"])],
            {"env_scanners": ["semgrep"]},
            id="a-null-list-that-is-replaced",
        ),
        pytest.param(
            {"extra_read_paths": ["/opt/a"]},
            [_op("replace", "/sandbox/extra_read_paths", ["/opt/c"])],
            {},
            id="a-list-the-file-wrote-is-not-a-limit",
        ),
    ],
)
def test_the_lists_a_patch_writes_where_the_file_wrote_none_are_returned_as_limits(
    tmp_path, written, operations, limits
):
    document: Dict[str, Any] = {"sandbox": written}
    if operations:
        document["patch"] = operations
    root = _config_of(tmp_path, document)

    _own, read_limits = _own_sandbox_read(root)

    assert read_limits == limits


def test_a_carried_document_is_read_instead_of_the_file(tmp_path):
    root = tmp_path / "cfg" / "carried.yaml"
    assert not root.exists()
    document = {"sandbox": {"mode": False, "extra_read_paths": ["rel"]}}

    own = _own_sandbox_settings(root, documents={root.resolve(): document})

    assert own == {
        "mode": "off",
        "extra_read_paths": [str(tmp_path.resolve() / "cfg" / "rel")],
    }
    # The caller's document is shared, so reading it changes nothing in it.
    assert document == {"sandbox": {"mode": False, "extra_read_paths": ["rel"]}}


def test_a_carried_documents_own_patch_is_applied(tmp_path):
    root = tmp_path / "cfg" / "carried.yaml"
    document = {
        "sandbox": {"mode": "bwrap"},
        "patch": [_op("replace", "/sandbox/mode", "auto")],
    }

    own = _own_sandbox_settings(root, documents={root.resolve(): document})

    assert own == {"mode": "auto"}


@pytest.mark.parametrize("carried", [{}, {"somewhere/else.yaml": {"sandbox": {}}}])
def test_a_carried_mapping_without_the_file_gives_nothing(
    tmp_path, carried: Optional[Dict[str, Any]]
):
    root = _config(tmp_path, "sandbox:\n  extra_read_paths:\n    - /opt/on-disk\n")
    documents = {Path(key): value for key, value in (carried or {}).items()}

    assert _own_sandbox_settings(root, documents=documents) == {}
