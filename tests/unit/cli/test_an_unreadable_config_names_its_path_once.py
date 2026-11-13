# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An unreadable config file is named once, with read advice, never format advice.

The refusal's own text names the file (describe_config_path), and the
OSError's text named it again: "could not read <p>: [Errno 13] Permission
denied: '<p>'". And the MCP get_config answer for a file that could not be
read carried ``error_category`` invalid_format, whose suggestions are about
file format and structure — wrong advice for a file whose bytes were never
read.
"""

from __future__ import annotations

import os
import re

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

_NEEDS_PERMISSION_BITS = pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs POSIX permission bits, which root reads past",
)

SESSION = "client-one"


@pytest.fixture
def unreadable(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / "ash.yaml"
    path.write_text("project_name: t\n", encoding="utf-8")
    path.chmod(0)
    yield path
    path.chmod(0o644)


def _squeezed(text: str) -> str:
    return re.sub(r"\s", "", text)


@_NEEDS_PERMISSION_BITS
def test_a_scan_names_the_unreadable_file_once(tmp_path, monkeypatch, unreadable):
    (tmp_path / "src").mkdir()
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--source-dir",
            str(tmp_path / "src"),
            "--output-dir",
            str(tmp_path / "out"),
            "--config",
            str(unreadable),
        ],
    )
    assert result.exit_code == 3, result.output
    # Under CI the console also shows the read-branch ERROR record, which names the
    # file on its own line; the claim is about the refusal, from its marker on.
    flat = _squeezed(result.output)
    marker = _squeezed("Invalid configuration:")
    assert flat.count(marker) == 1, result.output
    refusal = flat[flat.index(marker) :]
    assert refusal.count(_squeezed(str(unreadable))) == 1, result.output


@_NEEDS_PERMISSION_BITS
def test_config_get_names_the_unreadable_file_once(tmp_path, monkeypatch, unreadable):
    """Control: config get's own message already names the file once (the
    OSError's text, after a prefix with no path). The read-branch ERROR
    record above it names it separately, which is that record's own line."""
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["config", "get", "--config", str(unreadable)])
    assert result.exit_code == 3, result.output
    flat = _squeezed(result.output)
    marker = _squeezed("Could not read the config file:")
    assert flat.count(marker) == 1, result.output
    message = flat[flat.index(marker) :]
    assert message.count(_squeezed(str(unreadable))) == 1, result.output


@_NEEDS_PERMISSION_BITS
def test_mcp_get_config_answers_an_unreadable_file_as_a_read_failure(
    tmp_path, monkeypatch, unreadable
):
    """The category and its advice say the file could not be read, not that
    its format is wrong: no format was ever parsed."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    monkeypatch.setenv("ASH_CONFIG", str(unreadable))
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(tmp_path))
    # A given search_dir crosses the scan tool's root gate, so the session
    # needs the directory as a scan root for the call to reach the read this
    # cell is about.
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    response = mcp_get_config(search_dir=str(tmp_path), session_id=SESSION)

    assert response.get("success") is False, response
    assert response.get("error_category") == "permission_denied", response
    suggestions = " ".join(response.get("suggestions") or [])
    assert "permission" in suggestions.lower(), response
    assert "format" not in suggestions.lower(), response
    flat = _squeezed(str(response.get("error") or ""))
    assert flat.count(_squeezed(str(unreadable))) == 1, response
