# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""validate_config reads a remote caller's named file once, under the caller's rule.

Why this file exists
--------------------
For a remote caller ``config_sources.env_refused_for`` keeps every config file the
operator did not set aside from the environment, a named file outside the config
roots included. ``validate_config`` enforced that with a read of its own before the
validator ran, and then let the validator read the same chain again under the
default rule, which resolves every reference in a file that is not one a client
delivered. The refusal held only if no file changed between the two reads: a file
that gained a reference after the first was read by the validator with the
server's environment, and a reference to a variable that is not set was answered
with the validator's "not set" error, which says which of the server's variables
exist. A failure of the first read other than the refusal was dropped without a
word, on the grounds that the validator would report it.

The caller's rule now goes to the validator, which applies it in the one read it
makes (``ConfigValidator.check_config_file(refuse_env=...)``): a file the rule
refuses is refused before its references are resolved, whatever the file held
when the call started.

Why the cells are what they are
-------------------------------
The race cells rewrite the file in place right before the validator reads it,
which is the window between the two reads of the old shape. The variable they put
in the file is not set, so an answer that resolved it says so, and an answer
that did not says only that the file reads the environment.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    DEFAULT_SESSION_ID,
    clear_all_session_state,
    clear_profile_registry,
)
from automated_security_helper.cli.mcp_tools import mcp_validate_config
from automated_security_helper.config.config_validator import ConfigValidator

REMOTE = "client-1"
UNSET_VAR = "ASH_ONE_READ_UNSET_PROBE"
CLEAN = "project_name: clean-text\n"
READS_UNSET = f"project_name: ${{{UNSET_VAR}}}\n"
ENV_REFUSED = "config_env_not_resolved"


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    scan_root = tmp_path / "scan-root"
    (scan_root / "repo").mkdir(parents=True)
    operator = tmp_path / "operator"
    operator.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan_root))
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(operator))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.delenv(UNSET_VAR, raising=False)
    clear_profile_registry()
    clear_all_session_state()
    yield {"repo": scan_root / "repo", "operator": operator}
    clear_profile_registry()
    clear_all_session_state()


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _types(result: Dict[str, Any]) -> List[str]:
    return [error["type"] for error in result["errors"]]


def _before_the_validator_reads(monkeypatch, action: Callable[[], None]) -> list:
    """Run `action` right before the validator's check starts, and return the
    keyword arguments of each check, so a cell can see what the check was given."""
    real = ConfigValidator.check_config_file
    calls: list = []

    def act_then_check(*args, **kwargs):
        calls.append(kwargs)
        action()
        return real(*args, **kwargs)

    monkeypatch.setattr(
        ConfigValidator, "check_config_file", staticmethod(act_then_check)
    )
    return calls


def _rewrite_in_place(path: Path, text: str) -> Callable[[], None]:
    def rewrite() -> None:
        inode = os.stat(path).st_ino
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        assert os.stat(path).st_ino == inode, "premise: the same file was rewritten"

    return rewrite


def test_the_validator_is_given_the_callers_rule_for_a_remote_caller(
    _server, monkeypatch
):
    named = _write(_server["repo"] / "ash.yaml", CLEAN)
    operators = _write(_server["operator"] / "ash.yaml", CLEAN)
    calls = _before_the_validator_reads(monkeypatch, lambda: None)

    mcp_validate_config(config_path=str(named), session_id=REMOTE)
    mcp_validate_config(config_path=str(operators), session_id=REMOTE)

    assert len(calls) == 2, calls
    rule = calls[0].get("refuse_env")
    assert callable(rule), calls[0]
    assert rule(named) is True
    assert calls[1]["refuse_env"](operators) is False


def test_the_validator_is_given_the_local_callers_rule_which_keeps_a_file_in_the_scan_root(
    _server, monkeypatch
):
    named = _write(_server["repo"] / "ash.yaml", CLEAN)
    calls = _before_the_validator_reads(monkeypatch, lambda: None)

    mcp_validate_config(config_path=str(named), session_id=DEFAULT_SESSION_ID)

    assert len(calls) == 1, calls
    rule = calls[0].get("refuse_env")
    assert callable(rule), calls[0]
    assert rule(named) is False


@pytest.mark.parametrize("which", ["named", "base"])
def test_a_file_that_gains_a_reference_before_the_validator_reads_it_is_refused(
    _server, monkeypatch, which
):
    base = _write(_server["repo"] / "base.yaml", CLEAN)
    named = _write(_server["repo"] / "ash.yaml", "extends: base.yaml\n")
    changed = named if which == "named" else base
    text = READS_UNSET if which == "base" else f"extends: base.yaml\n{READS_UNSET}"
    calls = _before_the_validator_reads(monkeypatch, _rewrite_in_place(changed, text))

    result = mcp_validate_config(config_path=str(named), session_id=REMOTE)

    assert calls, "premise: the validator was called"
    assert result["valid"] is False, result
    assert _types(result) == [ENV_REFUSED], result
    # Refused before the reference was resolved: nothing says the variable is
    # unset, or which variable it was.
    assert UNSET_VAR not in json.dumps(result), result
    assert "not set" not in json.dumps(result), result


def test_control_a_file_that_reads_nothing_is_valid_for_a_remote_caller(_server):
    named = _write(_server["repo"] / "ash.yaml", CLEAN)

    result = mcp_validate_config(config_path=str(named), session_id=REMOTE)

    assert result["valid"] is True, result
    assert result["errors"] == [], result
