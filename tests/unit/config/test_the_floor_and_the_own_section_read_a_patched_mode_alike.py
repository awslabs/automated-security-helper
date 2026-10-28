# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The sandbox-mode floor and a file's own section read a patched mode alike.

A config file's own ``patch`` applies after the file, so the mode the file ends with
can come from an operation at the whole document, at ``/sandbox`` or at
``/sandbox/mode``. Two walks read those operations: the floor
(``_owned_sandbox_mode``), which decides the mode the scan may not go below, and the
file's own section (``_own_sandbox_settings``), which decides the settings the file
grants. They share one helper, ``_mode_after_patch``, which returns the mode after
the operations; each walk layers its own refusals on top:

- the floor spells every patched value (``False`` is the mode "off"; an unknown
  mode, or ``True``, refuses the load) and refuses a section written as something
  other than a mapping;
- the own section takes the value as written, so a patched ``False`` is not a mode
  and the section does not validate, which leaves the file with no grants.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ASHConfigValidationError


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    # A basetemp inside a checkout would make every file here the repository's,
    # and the section's cells would pass for the wrong reason.
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    for directory in (tmp_path, *tmp_path.parents):
        assert not os.path.lexists(directory / ".git"), (
            f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
        )


def _op(op: str, path: str, value: Any = None) -> Dict[str, Any]:
    operation: Dict[str, Any] = {"op": op, "path": path}
    if op != "remove":
        operation["value"] = value
    return operation


#: (the mode before, the operations, the mode after).
CASES = [
    pytest.param(
        "bwrap", [_op("add", "/sandbox", {"mode": "off"})], "off", id="section-mode"
    ),
    pytest.param(
        "bwrap", [_op("replace", "/sandbox/mode", "auto")], "auto", id="replaced"
    ),
    pytest.param(
        None, [_op("add", "/sandbox/mode", "firejail")], "firejail", id="added"
    ),
    pytest.param(
        "bwrap",
        [_op("add", "/sandbox/mode", "firejail"), _op("replace", "/sandbox/mode", "x")],
        "x",
        id="in-order",
    ),
    pytest.param("bwrap", [_op("remove", "/sandbox/mode")], None, id="mode-removed"),
    pytest.param("bwrap", [_op("remove", "/sandbox")], None, id="section-removed"),
    pytest.param("bwrap", [_op("add", "/sandbox", {})], None, id="section-no-mode"),
    pytest.param(
        "bwrap", [_op("add", "", {"project_name": "x"})], None, id="document-no-mode"
    ),
    pytest.param(
        "bwrap",
        [_op("add", "", {"sandbox": {"mode": "auto"}})],
        "auto",
        id="document-mode",
    ),
    pytest.param(
        "bwrap", [_op("remove", "")], "bwrap", id="the-document-cannot-be-removed"
    ),
    pytest.param(
        "bwrap",
        [_op("test", "/sandbox/mode", "bwrap")],
        "bwrap",
        id="test-sets-nothing",
    ),
    pytest.param(
        "bwrap",
        [{"op": "move", "from": "/elsewhere", "path": "/sandbox/mode"}],
        "bwrap",
        id="move-sets-nothing",
    ),
    pytest.param(
        "bwrap", [_op("replace", "/sandbox/extra_read_paths", [])], "bwrap", id="other"
    ),
    pytest.param("bwrap", [_op("add", "/sandbox", "text")], "bwrap", id="not-a-map"),
    pytest.param("bwrap", ["not an operation", 3, None], "bwrap", id="not-operations"),
    pytest.param("bwrap", None, "bwrap", id="no-patch"),
    pytest.param(
        "bwrap", [_op("replace", "/sandbox/mode", False)], False, id="false-as-given"
    ),
]


@pytest.mark.parametrize("before, operations, after", CASES)
def test_the_helper_returns_the_mode_after_the_operations(before, operations, after):
    from automated_security_helper.config.resolve_config import _mode_after_patch

    result = _mode_after_patch(before, operations)

    assert result == after
    assert type(result) is type(after)


def test_the_helper_spells_each_patched_value_even_when_a_later_one_replaces_it():
    from automated_security_helper.config.resolve_config import _mode_after_patch

    seen: List[Any] = []

    def spell(value: Any) -> str:
        seen.append(value)
        if value == "bogus":
            raise ValueError("refused")
        return f"<{value}>"

    with pytest.raises(ValueError):
        _mode_after_patch(
            "bwrap",
            [
                _op("replace", "/sandbox/mode", "bogus"),
                _op("add", "/sandbox/mode", "x"),
            ],
            spell=spell,
        )
    assert seen == ["bogus"]
    assert (
        _mode_after_patch(
            "bwrap",
            [_op("replace", "/sandbox/mode", "auto")],
            spell=spell,
        )
        == "<auto>"
    )


def test_the_helper_reports_a_section_written_as_something_other_than_a_mapping():
    from automated_security_helper.config.resolve_config import _mode_after_patch

    reported: List[str] = []

    def refuse() -> None:
        reported.append("reported")

    _mode_after_patch("bwrap", [_op("add", "/sandbox", "text")], on_non_mapping=refuse)
    _mode_after_patch("bwrap", [_op("add", "", {"sandbox": 3})], on_non_mapping=refuse)
    # A missing value is not a value written over the section.
    _mode_after_patch("bwrap", [_op("add", "/sandbox", None)], on_non_mapping=refuse)

    assert reported == ["reported", "reported"]


# --- Each walk's layer on top ---------------------------------------------------


def _floor(tmp_path: Path, patch: List[Any]) -> Any:
    from automated_security_helper.config.resolve_config import _owned_sandbox_mode

    root = tmp_path / "operator.yaml"
    document = {"sandbox": {"mode": "bwrap"}, "patch": patch}
    return _owned_sandbox_mode([root], [], {root.resolve(): document}, frozenset())


def test_the_floor_reads_a_patched_false_as_the_mode_off(tmp_path):
    assert _floor(tmp_path, [_op("replace", "/sandbox/mode", False)]) == "off"


@pytest.mark.parametrize("value", ["bogus", True, None])
def test_the_floor_refuses_a_patched_value_that_names_no_mode(tmp_path, value):
    with pytest.raises(ASHConfigValidationError):
        _floor(tmp_path, [_op("replace", "/sandbox/mode", value)])


def test_the_floor_refuses_an_unknown_mode_a_later_operation_replaces(tmp_path):
    with pytest.raises(ASHConfigValidationError):
        _floor(
            tmp_path,
            [
                _op("replace", "/sandbox/mode", "bogus"),
                _op("replace", "/sandbox/mode", "auto"),
            ],
        )


def test_the_floor_refuses_a_section_written_as_something_other_than_a_mapping(
    tmp_path,
):
    with pytest.raises(ASHConfigValidationError):
        _floor(tmp_path, [_op("add", "/sandbox", "text")])


def test_control_the_floor_reads_the_modes_the_walk_has_always_read(tmp_path):
    assert _floor(tmp_path, []) == "bwrap"
    assert _floor(tmp_path, [_op("replace", "/sandbox/mode", "auto")]) == "auto"
    assert _floor(tmp_path, [_op("remove", "/sandbox/mode")]) is None
    assert _floor(tmp_path, [_op("add", "/sandbox", {})]) is None


def test_the_own_section_does_not_adopt_a_patched_false(tmp_path):
    """The section holds the value as written; it does not validate as a sandbox, so
    the file keeps no grants (the config loader refuses a patched boolean too)."""
    from automated_security_helper.config.resolve_config import (
        _own_sandbox_settings,
        _with_own_sandbox,
    )

    root = tmp_path / "ops" / "root.yaml"
    document = {
        "sandbox": {"mode": "bwrap", "env_scanners": ["semgrep"]},
        "patch": [_op("replace", "/sandbox/mode", False)],
    }
    documents = {root.resolve(): document}

    assert _own_sandbox_settings(root, documents=documents)["mode"] is False
    trusted = AshConfig()
    updated, wrote_mode = _with_own_sandbox(
        trusted, root, tmp_path / "repo", [root], [tmp_path / "repo"], None, documents
    )
    assert wrote_mode is False
    assert updated.sandbox.env_scanners == []
