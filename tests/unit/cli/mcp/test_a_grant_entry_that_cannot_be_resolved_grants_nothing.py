# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One unresolvable entry in a grant does not make every gate raise.

``ASH_MCP_ALLOWED_ROOTS`` and ``ASH_MCP_ALLOWED_CONFIG_ROOTS`` are parsed with
``Path(entry).expanduser().resolve()``. On Python 3.12 and older ``resolve`` raises
``RuntimeError`` for a symbolic link that leads back to itself, and ``expanduser``
raises it for a ``~`` entry when no home directory can be found. The gates catch
``ValueError`` and ``OSError`` only, so one such entry made every gate that reads a
grant raise, the refusals included, and a remote caller got an internal error
where the sandbox owed it a refusal. The entry now grants nothing and is left out
with a warning; the denylist keeps a root it cannot resolve as spelled.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.config import mcp_sandbox

pytestmark = pytest.mark.unit


@pytest.fixture
def a_path_named_loop_cannot_be_resolved(monkeypatch):
    """``Path.resolve`` raises the way a link loop does for a path named ``loop``."""
    real = Path.resolve

    def resolve(self, *args, **kwargs):
        if self.name == "loop":
            raise RuntimeError(f"Symlink loop from {self}")
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve)


def test_control_a_resolvable_grant_is_parsed(tmp_path):
    assert mcp_sandbox._parse_roots(str(tmp_path)) == (tmp_path.resolve(),)


def test_an_entry_that_cannot_be_resolved_is_left_out_not_raised(
    tmp_path, a_path_named_loop_cannot_be_resolved
):
    """Red at the base: ``RuntimeError`` from the parse."""
    good = tmp_path / "good"
    good.mkdir()
    raw = os.pathsep.join([str(tmp_path / "loop"), str(good)])

    assert mcp_sandbox._parse_roots(raw) == (good.resolve(),)


def test_the_gates_still_answer_with_one_bad_entry_in_the_grant(
    tmp_path, monkeypatch, a_path_named_loop_cannot_be_resolved
):
    from automated_security_helper.cli.mcp.scan_target import validate_scan_target

    good = tmp_path / "good"
    good.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setenv(
        "ASH_MCP_ALLOWED_ROOTS", os.pathsep.join([str(tmp_path / "loop"), str(good)])
    )
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))

    assert validate_scan_target(good) is None
    assert validate_scan_target(outside) is not None


def test_a_denied_root_that_cannot_be_resolved_is_kept_as_spelled(
    tmp_path, monkeypatch, a_path_named_loop_cannot_be_resolved
):
    """The denylist fails to the safe side: the root stays refused."""
    unresolvable = tmp_path / "loop"
    monkeypatch.setattr(mcp_sandbox, "_denied_root_values", lambda: [str(unresolvable)])

    assert mcp_sandbox._denied_roots() == [unresolvable]
