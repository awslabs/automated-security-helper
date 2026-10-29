# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A client's config file that does not parse is refused without quoting it.

A YAML parser's message repeats the line it stopped at. For a file an MCP client
delivered or named, that line is text the client may not have written: a
delivered link can reach a file on the server. So each way ASH reads such a file
reports only the parser's error type and position (``resolve_config.
_unquoted_load_error``), and raises with no cause or context that holds the
parser's error. These tests read a file that fails on a line holding a marker
and check the marker is in none of the message, the arguments, the cause, the
context and the log, along three paths: a base a client's file extends, a
workspace overlay a client delivered, and a delivered ``ASH_CONFIG`` under
strict resolution.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import ASHConfigValidationError

pytestmark = pytest.mark.unit

CANARY = "secret-canary-91f3"
#: An alias to an anchor that is not defined: the parser stops on this line and
#: quotes it.
DOES_NOT_PARSE = f"project_name: *{CANARY}\n"


@pytest.fixture
def mcp_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "mcp-workspaces"
    (root / "session-1" / "source").mkdir(parents=True)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    return root


@pytest.fixture
def delivered(mcp_root: Path) -> Path:
    return mcp_root / "session-1" / "source"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    return root


def _refused_without_the_canary(error: BaseException, log: str) -> None:
    assert isinstance(error, ASHConfigValidationError), repr(error)
    seen = set()
    current: Any = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        assert CANARY not in str(current), current
        assert CANARY not in repr(current.args), current.args
        current = current.__cause__ or current.__context__
    assert error.__cause__ is None
    assert error.__context__ is None
    assert CANARY not in log


def test_a_base_a_client_file_extends(
    delivered: Path, repo: Path, caplog: pytest.LogCaptureFixture
) -> None:
    (delivered / "base.yaml").write_text(DOES_NOT_PARSE, encoding="utf-8")
    root = delivered / "ash.yaml"
    root.write_text("project_name: x\nextends: base.yaml\n", encoding="utf-8")

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(Exception) as raised:
            resolve_config(config_path=root, source_dir=repo, untrusted_config=True)

    _refused_without_the_canary(raised.value, caplog.text)
    assert "base.yaml" in str(raised.value)


def test_a_workspace_overlay_a_client_delivered(
    delivered: Path, repo: Path, caplog: pytest.LogCaptureFixture
) -> None:
    overlay = delivered / "workspace.yaml"
    overlay.write_text(DOES_NOT_PARSE, encoding="utf-8")

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(Exception) as raised:
            resolve_config(source_dir=repo, overlay_config_path=overlay)

    _refused_without_the_canary(raised.value, caplog.text)


def test_a_delivered_ash_config_beside_the_operators_config(
    tmp_path: Path,
    delivered: Path,
    repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Strict resolution, as ``ash merge`` and ``ash config`` resolve the operator's
    --config: ASH_CONFIG's file is still read, and is refused as the file it is,
    not as a raw parser error that blames the operator's file."""
    ops = tmp_path / "ops"
    ops.mkdir()
    operator = ops / "ash.yaml"
    operator.write_text("project_name: operator\n", encoding="utf-8")
    ash_config = delivered / "ash.yaml"
    ash_config.write_text(DOES_NOT_PARSE, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(ash_config))

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(Exception) as raised:
            resolve_config(
                config_path=operator, source_dir=repo, fallback_to_default=False
            )

    _refused_without_the_canary(raised.value, caplog.text)
    assert "ash.yaml" in str(raised.value)
    assert str(operator) not in str(raised.value)


def test_control_an_operator_file_keeps_the_parsers_message(
    tmp_path: Path, repo: Path, mcp_root: Path
) -> None:
    """Outside the MCP root and outside every checkout, the file is the operator's."""
    ops = tmp_path / "ops"
    ops.mkdir()
    (ops / "base.yaml").write_text(DOES_NOT_PARSE, encoding="utf-8")
    root = ops / "ash.yaml"
    root.write_text("project_name: x\nextends: base.yaml\n", encoding="utf-8")

    with pytest.raises(ASHConfigValidationError) as raised:
        resolve_config(config_path=root, source_dir=repo)

    assert CANARY in str(raised.value)
