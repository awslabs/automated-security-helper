# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Files an MCP client delivered count as the scanned party's, wherever they are.

A config an MCP client uploads is resolved with ``untrusted_config=True``. The
files it can point a scanner or the plugin loader at include everything else a
client delivered under the MCP workspace root: another session's tree, an upload
or its staging. Those are outside the tree being scanned, so the tree test alone
would accept them. ``path_trust.in_scanned_tree`` also refuses them, except for a
session's ``config/`` directory, which only the server writes.
"""

import sys

import pytest

from automated_security_helper.config.path_trust import (
    honored_path,
    in_scanned_tree,
    reset_path_refusal_warnings,
)
from automated_security_helper.config.plugin_module_trust import refusal_reason
from automated_security_helper.config.resolve_config import resolve_config


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    root = tmp_path / "ash-mcp"
    for session in ("session-a", "session-b"):
        (root / session / "source").mkdir(parents=True)
        (root / session / "config").mkdir(parents=True)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    reset_path_refusal_warnings()
    yield root
    reset_path_refusal_warnings()


def test_a_file_in_another_session_is_not_passed_to_a_tool(workspace):
    source = workspace / "session-a" / "source"
    other = workspace / "session-b" / "source" / "checkov.yaml"
    other.write_text("")
    assert honored_path(other, source_dir=source, key="k") is None


def test_an_upload_outside_any_session_tree_is_not_passed(workspace):
    source = workspace / "session-a" / "source"
    staged = workspace / "session-a" / "upload-staging" / "ferret.yaml"
    staged.parent.mkdir()
    staged.write_text("")
    assert honored_path(staged, source_dir=source, key="k") is None


def test_a_server_written_session_config_file_is_passed(workspace):
    source = workspace / "session-a" / "source"
    profile = workspace / "session-a" / "config" / "checkov.yaml"
    profile.write_text("")
    assert honored_path(profile, source_dir=source, key="k") == profile.resolve()


def test_outside_the_mcp_workspace_nothing_changes(workspace, tmp_path):
    source = workspace / "session-a" / "source"
    operator = tmp_path / "operator" / "checkov.yaml"
    operator.parent.mkdir()
    operator.write_text("")
    assert not in_scanned_tree(operator, source)
    assert honored_path(operator, source_dir=source, key="k") == operator.resolve()


def test_a_plugin_module_delivered_by_a_client_is_refused(workspace, monkeypatch):
    source = workspace / "session-a" / "source"
    site = workspace / "session-b" / "source"
    package = site / "standin_delivered"
    package.mkdir()
    (package / "__init__.py").write_text("DELIVERED_LOADED = True\n")
    monkeypatch.syspath_prepend(str(site))
    try:
        assert refusal_reason("standin_delivered", source) is not None
        assert "standin_delivered" not in sys.modules
    finally:
        sys.modules.pop("standin_delivered", None)


def test_an_uploaded_config_cannot_add_an_uninstalled_module(workspace):
    source = workspace / "session-a" / "source"
    upload = workspace / "session-a" / "upload-staging" / "ash.yaml"
    upload.parent.mkdir()
    upload.write_text(
        "project_name: uploaded\nash_plugin_modules:\n"
        "  - no_such_module_anywhere\n"
        "  - automated_security_helper.plugin_modules.ash_trivy_plugins\n"
    )
    config = resolve_config(
        config_path=upload,
        source_dir=source,
        untrusted_config=True,
        fallback_to_default=True,
    )
    assert config.ash_plugin_modules == [
        "automated_security_helper.plugin_modules.ash_trivy_plugins"
    ]
