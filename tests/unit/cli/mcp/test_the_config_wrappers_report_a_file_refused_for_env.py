# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``validate_config_chain`` and ``config_load_error`` report a file refused for ``!ENV``.

Both are one field each of ``check_config_input``'s answer, and a file a remote
caller may not read with ``!ENV`` that uses it comes back as ``env_error``, a third
field neither wrapper returned. ``config_load_error`` said None (its docstring: "the
config loads and validates") for such a file, so a caller that followed its own
instruction to call it before starting a scan started one that then failed on the
same file. Each wrapper now answers the refusal as an error.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config import mcp_sandbox
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _local_transport(monkeypatch, tmp_path):
    monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)


@pytest.fixture
def a_file_the_caller_may_not_read_with_env(tmp_path, monkeypatch):
    """A config using ``!ENV`` that this caller's rule refuses it for."""
    monkeypatch.setattr(mcp_sandbox, "caller_is_remote", lambda *a, **k: True)
    monkeypatch.setattr(
        mcp_sandbox, "client_named_config_is_untrusted", lambda *a, **k: True
    )
    config = tmp_path / ".ash.yaml"
    config.write_text("project_name: !ENV SOME_VARIABLE_NOBODY_SET\n", encoding="utf-8")
    return config


def test_control_check_config_input_carries_the_refusal_as_env_error(
    a_file_the_caller_may_not_read_with_env,
):
    checked = mcp_sandbox.check_config_input(a_file_the_caller_may_not_read_with_env)

    assert checked.env_error is not None
    assert checked.refusal is None and checked.load_error is None


def test_config_load_error_reports_the_file_as_one_that_does_not_load(
    a_file_the_caller_may_not_read_with_env,
):
    """Red at the base: None, "the config loads and validates"."""
    error = mcp_sandbox.config_load_error(a_file_the_caller_may_not_read_with_env)

    assert isinstance(error, MCPResourceError)
    assert "!ENV" in str(error)
    assert error.context["error_type"] == "config_env_not_resolved"
    assert "SOME_VARIABLE_NOBODY_SET" not in str(error)


def test_validate_config_chain_reports_the_file_too(
    a_file_the_caller_may_not_read_with_env,
):
    """Red at the base: None, so a caller that stops at this answer starts a scan
    that fails on the same file."""
    error = mcp_sandbox.validate_config_chain(a_file_the_caller_may_not_read_with_env)

    assert isinstance(error, MCPResourceError)
    assert error.context["error_type"] == "config_env_not_resolved"


def test_a_file_with_no_env_reference_is_still_answered_none(tmp_path):
    """Control: the wrappers still say None for a config that loads."""
    config = tmp_path / ".ash.yaml"
    config.write_text("project_name: plain\n", encoding="utf-8")

    assert mcp_sandbox.config_load_error(config) is None
    assert mcp_sandbox.validate_config_chain(config) is None


def test_discovery_still_leaves_the_env_refusal_to_the_scans_own_read(
    a_file_the_caller_may_not_read_with_env,
):
    """``validate_discovered_config`` answers refusals of the path only: a file
    refused for ``!ENV`` is reported by the callers that read the chain
    themselves (``config_env_not_resolved``), as it was before the wrappers
    surfaced it."""
    target = a_file_the_caller_may_not_read_with_env.parent

    assert mcp_sandbox.validate_discovered_config(target) is None
