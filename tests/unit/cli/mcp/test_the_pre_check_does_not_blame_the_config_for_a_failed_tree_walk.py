# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A failed walk of the source tree is not the named config's read failure.

``_config_pre_check`` builds the settings a scan reads the chain with from the
trees the scan targets (``scanned_trees(source_dir)``). That walk was inside the
try that turns an OSError of the NAMED FILE into the refusal ``could not read
<file>``, so a link loop in the source tree, or a directory the server cannot
read above it, was reported as the config's own read failure with exit 3. The
walk now has its own handler: the pre-check answers nothing, and the scan, which
walks the same tree, reports its own failure.
"""

from __future__ import annotations

import errno
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

SESSION = "client-one"


@pytest.fixture
def layout(tmp_path, monkeypatch) -> Path:
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    source = tmp_path / "scan"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    named = tmp_path / "elsewhere" / "ash.yaml"
    named.parent.mkdir()
    named.write_text("project_name: named\n", encoding="utf-8")
    return tmp_path


def test_a_failed_walk_of_the_source_tree_leaves_the_config_unblamed(
    layout: Path, monkeypatch
) -> None:
    from automated_security_helper.cli.mcp_tools import _config_pre_check
    from automated_security_helper.config import sandbox_grants

    def a_link_loop(root, *args, **kwargs):
        raise OSError(errno.ELOOP, "Too many levels of symbolic links", str(root))

    monkeypatch.setattr(sandbox_grants, "scanned_trees", a_link_loop)

    pre_check = _config_pre_check(
        layout / "elsewhere" / "ash.yaml", layout / "scan", SESSION
    )

    assert pre_check.load_refusal is None, (
        "the failed walk of the source tree was reported as the config's read failure"
    )
    assert pre_check.env_refusal is None
    assert pre_check.environment_values == ()


def test_a_read_failure_after_the_walk_keeps_the_load_refusal(
    layout: Path, monkeypatch
) -> None:
    """The handler covers the walk and nothing after it. The settings built from
    the trees are the next step, and an OSError raised there is not a tree walk:
    it may be a chain file's read, so the pre-check keeps the refusal that names
    the file instead of answering nothing."""
    from automated_security_helper.cli.mcp_tools import _config_pre_check
    from automated_security_helper.config import operator_only_options

    named = layout / "elsewhere" / "ash.yaml"

    def a_chain_file_that_cannot_be_read(trees, every_file=False):
        raise OSError(errno.EACCES, "Permission denied", str(named))

    monkeypatch.setattr(
        operator_only_options,
        "scan_repository_settings",
        a_chain_file_that_cannot_be_read,
    )

    pre_check = _config_pre_check(named, layout / "scan", SESSION)

    assert pre_check.load_refusal is not None, (
        "a read failure after the walk was answered as no refusal at all"
    )
    assert "could not read" in str(pre_check.load_refusal[1])


def test_a_failed_read_of_the_named_file_is_still_its_load_refusal(
    layout: Path, monkeypatch
) -> None:
    """The control: an OSError of the named path itself keeps its refusal."""
    from automated_security_helper.cli.mcp import sandbox
    from automated_security_helper.cli.mcp_tools import _config_pre_check

    named = layout / "elsewhere" / "ash.yaml"

    def a_link_loop(path, *, session_id=None):
        raise OSError(errno.ELOOP, "Too many levels of symbolic links", str(path))

    monkeypatch.setattr(sandbox, "client_named_config_is_untrusted", a_link_loop)

    pre_check = _config_pre_check(named, layout / "scan", SESSION)

    assert pre_check.load_refusal is not None, pre_check
    assert "could not read" in str(pre_check.load_refusal[1])
