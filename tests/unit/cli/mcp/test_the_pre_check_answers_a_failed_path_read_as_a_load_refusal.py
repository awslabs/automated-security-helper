# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan tool's config pre-check answers a failed read of the named path as a refusal.

``_config_pre_check`` judges a named config with the scan's own predicate
(``sandbox.client_named_config_is_untrusted``), which reads the filesystem: a
resolve and a samefile. A link loop at the named path, or its directory gone
since the request was made, raises an OSError there. Raised before the
pre-check's own try began, it left the function as an exception, through the
thread the start path runs it in, and the start answered an internal error
with a traceback instead of the read refusal the same path gets when the file
itself cannot be read (``could not read <file>``, exit 3).
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


def test_a_predicate_read_that_fails_is_the_named_files_load_refusal(
    layout: Path, monkeypatch
) -> None:
    """Red at the base: the OSError left _config_pre_check as an exception."""
    from automated_security_helper.cli.mcp import sandbox
    from automated_security_helper.cli.mcp_tools import _config_pre_check

    named = layout / "elsewhere" / "ash.yaml"

    def a_link_loop(path, *, session_id=None):
        raise OSError(errno.ELOOP, "Too many levels of symbolic links", str(path))

    monkeypatch.setattr(sandbox, "client_named_config_is_untrusted", a_link_loop)

    pre_check = _config_pre_check(named, layout / "scan", SESSION)

    assert pre_check.env_refusal is None
    assert pre_check.load_refusal is not None, pre_check
    refused_path, refusal = pre_check.load_refusal
    assert refused_path == named
    assert "could not read" in str(refusal), str(refusal)
    assert "Too many levels of symbolic links" in str(refusal), str(refusal)


def test_a_predicate_that_answers_leaves_the_file_to_the_scan(layout: Path) -> None:
    """Control: with the predicate reading normally, the same file pre-checks
    clean, so the refusal above is the failed read's and not the file's."""
    from automated_security_helper.cli.mcp_tools import _config_pre_check

    named = layout / "elsewhere" / "ash.yaml"

    pre_check = _config_pre_check(named, layout / "scan", SESSION)

    assert pre_check.env_refusal is None and pre_check.load_refusal is None
