# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan grant that is configured but resolves to nothing denies; it does not widen.

``session_sandbox`` selects the permissive denylist path when no grant applies
and the caller is local. ``_parse_roots`` drops every entry it cannot resolve, so
a ``ASH_MCP_ALLOWED_ROOTS`` whose only entry cannot be resolved came back empty
and was indistinguishable from no grant at all: the operator asked to narrow
the server to a directory and got the widest reach instead. A grant that is set
and yields no usable root now denies, and the refusal names the variable.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.config import mcp_sandbox

pytestmark = pytest.mark.unit


@pytest.fixture
def a_path_named_loop_cannot_be_resolved(monkeypatch):
    real = Path.resolve

    def resolve(self, *args, **kwargs):
        if self.name == "loop":
            raise RuntimeError(f"Symlink loop from {self}")
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve)


@pytest.fixture
def local_transport(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)


def test_control_no_grant_keeps_the_local_denylist_fallback(local_transport):
    sandbox = mcp_sandbox.session_sandbox(None)

    assert sandbox.fall_back_to_denylist is True


def test_control_a_resolvable_grant_does_not_fall_back(
    tmp_path, monkeypatch, local_transport
):
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))

    assert mcp_sandbox.session_sandbox(None).fall_back_to_denylist is False


def test_a_blank_or_separator_only_grant_counts_as_no_grant(
    monkeypatch, local_transport
):
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", os.pathsep + "  " + os.pathsep)

    assert mcp_sandbox.session_sandbox(None).fall_back_to_denylist is True


def test_a_configured_grant_that_resolves_to_nothing_does_not_fall_back(
    tmp_path, monkeypatch, local_transport, a_path_named_loop_cannot_be_resolved
):
    """Red at the base: the sandbox fell back to the permissive denylist."""
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "loop"))

    sandbox = mcp_sandbox.session_sandbox(None)

    assert sandbox.fall_back_to_denylist is False
    assert sandbox.scan_roots == ()


def test_a_scan_outside_an_unresolvable_grant_is_refused_naming_the_variable(
    tmp_path, monkeypatch, local_transport, a_path_named_loop_cannot_be_resolved
):
    from automated_security_helper.cli.mcp.scan_target import validate_scan_target

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "loop"))

    refusal = validate_scan_target(elsewhere)

    assert refusal is not None
    assert "ASH_MCP_ALLOWED_ROOTS" in str(refusal)
    assert "none of its entries could be resolved" in str(refusal)
    assert str(tmp_path / "loop") not in str(refusal)


def test_the_degraded_gate_sandbox_denies_too(
    tmp_path, monkeypatch, local_transport, a_path_named_loop_cannot_be_resolved
):
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "loop"))
    monkeypatch.setattr(
        mcp_sandbox,
        "session_sandbox",
        lambda session_id=None: (_ for _ in ()).throw(ValueError("bad id")),
    )

    sandbox = mcp_sandbox._sandbox_for_gate("bad id")

    assert sandbox.fall_back_to_denylist is False
    assert sandbox.scan_roots == ()


def test_the_profile_scan_root_check_is_sane_with_no_resolved_root(
    tmp_path, monkeypatch, local_transport, a_path_named_loop_cannot_be_resolved
):
    """``operator_scan_roots`` is also read when judging a profile's location."""
    from automated_security_helper.config import session_profiles

    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path / "loop"))
    (tmp_path / ".git").mkdir()
    profile = tmp_path / "profile.yaml"
    profile.write_text("{}\n")

    assert mcp_sandbox.operator_scan_roots() == ()
    assert session_profiles._profile_kept_where_a_scan_may_rewrite_it(profile) is None
