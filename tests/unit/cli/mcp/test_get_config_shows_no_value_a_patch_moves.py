# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_config shows no value a config's ``patch`` reads from the environment.

get_config shows a value a config file read from the environment as
``<from ${VAR}>`` at the place the load recorded for it, and every other entry
as written. A ``patch`` operation's reference recorded at index 0 of its
list whatever the operation's path said would have the entry it added at the end
(or anywhere past 0) come back with the value, and entry 0 marked instead.

Two rules, as a scan applies them:

- A config file an MCP client delivered reads nothing from the environment: one
  that uses ``!ENV`` or a ``${VAR}`` reference is refused with
  ``config_env_not_resolved`` before any value is read.
- In the operator's file, a reference is recorded where its value lands once
  the file's patch has applied, the later operations included: an append, an
  insert in front of it, a remove before or after it, a replace of another
  entry, a test. A value the patch writes over is no longer there and is not
  marked. The same for a base's reference the extending file's patch moves.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import pytest

from automated_security_helper.cli.mcp_tools import mcp_get_config

pytestmark = pytest.mark.unit

#: Long enough that no other text of the response holds it by chance.
VALUE = "value-from-the-servers-environment"
POINTER = "/global_settings/ignore_paths"


@pytest.fixture(autouse=True)
def _environment(monkeypatch):
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _op(op: str, path: str, value: Optional[str] = None, source: str = "") -> str:
    """One patch operation in block style: a plain ``${VAR}`` in a flow mapping
    would end at its brace. ``value`` is an ignore path entry's path, written
    as given (quoted or plain)."""
    lines = [f"  - op: {op}\n", f"    path: {POINTER}/{path}\n"]
    if source:
        lines.append(f"    from: {POINTER}/{source}\n")
    if value is not None:
        lines.append(f"    value:\n      path: {value}\n      reason: r\n")
    return "".join(lines)


def _config(ops: List[str]) -> str:
    return (
        "project_name: demo\n"
        "global_settings:\n"
        "  ignore_paths:\n"
        "    - path: kept\n"
        "      reason: r\n"
        "patch:\n" + "".join(ops)
    )


def _add(index: str, path: str) -> str:
    return _op("add", index, path)


def _paths(result) -> List[str]:
    assert result.get("success") is not False, result
    return [entry["path"] for entry in result["global_settings"]["ignore_paths"]]


def _no_value(result) -> None:
    assert VALUE not in json.dumps(result, default=str), result


MARKED = "<from ${ASH_X}>"

#: Each operator file's patch, and the paths get_config shows after it.
OPERATOR_SHAPES = {
    "append": ([_add("-", "${ASH_X}")], ["kept", MARKED]),
    "insert-in-front": ([_add("0", "${ASH_X}")], [MARKED, "kept"]),
    "insert-then-insert": (
        [_add("0", "${ASH_X}"), _add("0", "lit")],
        ["lit", MARKED, "kept"],
    ),
    "append-twice": (
        [_add("-", "${ASH_X}"), _add("-", "lit")],
        ["kept", MARKED, "lit"],
    ),
    "append-after-a-literal": (
        [_add("-", "lit"), _add("-", "${ASH_X}")],
        ["kept", "lit", MARKED],
    ),
    "add-then-remove-before": (
        [_add("-", "${ASH_X}"), _op("remove", "0")],
        [MARKED],
    ),
    "remove-after": (
        [_add("0", "${ASH_X}"), _op("remove", "1")],
        [MARKED],
    ),
    "replace-before": (
        [_add("-", "${ASH_X}"), _op("replace", "0", "lit")],
        ["lit", MARKED],
    ),
    "test-after": (
        [_add("-", "${ASH_X}"), _op("test", "0", "kept")],
        ["kept", MARKED],
    ),
    "written-over": (
        [_add("-", "${ASH_X}"), _op("replace", "1", "lit")],
        ["kept", "lit"],
    ),
}


@pytest.mark.parametrize("shape", sorted(OPERATOR_SHAPES))
def test_an_operator_file_s_patched_value_is_marked_where_it_lands(
    tmp_path, monkeypatch, shape
):
    ops, shown = OPERATOR_SHAPES[shape]
    monkeypatch.setenv("ASH_X", VALUE)
    config = tmp_path / "operator" / ".ash.yaml"
    config.parent.mkdir()
    config.write_text(_config(ops), encoding="utf-8")

    result = mcp_get_config(config_path=str(config))

    assert _paths(result) == shown, result
    _no_value(result)


def test_a_base_s_value_the_extending_file_s_patch_moves_is_marked_where_it_lands(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("ASH_X", VALUE)
    project = tmp_path / "operator"
    project.mkdir()
    (project / "base.yaml").write_text(
        "global_settings:\n  ignore_paths:\n    - path: ${ASH_X}\n      reason: r\n",
        encoding="utf-8",
    )
    config = project / ".ash.yaml"
    config.write_text(
        "project_name: demo\nextends: base.yaml\npatch:\n" + _add("0", "lit"),
        encoding="utf-8",
    )

    result = mcp_get_config(config_path=str(config))

    assert _paths(result) == ["lit", MARKED], result
    _no_value(result)


#: Each client file: a patch that reads the environment, or a plain reference,
#: as a value or as a mapping's key (block style: a plain ${VAR} key in a flow
#: mapping would end at its brace).
CLIENT_SHAPES = {
    "append": _config([_add("-", "${VAR}")]),
    "insert-twice": _config([_add("0", "${VAR}"), _add("0", "${VAR}")]),
    "direct": "project_name: ${VAR}\n",
    "env-tag": "project_name: !ENV ${VAR}\n",
    "key": "project_name: demo\nreporters:\n  ${VAR}:\n    enabled: false\n",
}


def _delivered(tmp_path, monkeypatch, text: str) -> Path:
    workspace = tmp_path / "workspaces"
    delivered = workspace / "session-a" / "source"
    delivered.mkdir(parents=True)
    config = delivered / ".ash.yaml"
    config.write_text(text, encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    return config


@pytest.mark.parametrize(
    "variable", ["ASH_X", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE"]
)
@pytest.mark.parametrize("shape", sorted(CLIENT_SHAPES))
def test_a_client_file_that_reads_the_environment_is_refused(
    tmp_path, monkeypatch, shape, variable
):
    monkeypatch.setenv(variable, VALUE)
    config = _delivered(
        tmp_path, monkeypatch, CLIENT_SHAPES[shape].replace("VAR", variable)
    )

    result = mcp_get_config(config_path=str(config), session_id="session-a")

    _no_value(result)
    assert result.get("success") is False, result
    assert result["error_type"] == "config_env_not_resolved", result


def test_control_a_client_file_that_reads_nothing_from_the_environment_loads(
    tmp_path, monkeypatch
):
    """The same patch with literal values: the client's file is shown as is,
    and a quoted YAML string that only looks like a reference is a literal."""
    config = _delivered(
        tmp_path,
        monkeypatch,
        _config([_add("-", "lit"), _add("0", "'${ASH_X}'")]),
    )
    monkeypatch.setenv("ASH_X", VALUE)

    result = mcp_get_config(config_path=str(config), session_id="session-a")

    assert _paths(result) == ["${ASH_X}", "kept", "lit"], result
    _no_value(result)


def test_a_scan_s_load_refuses_the_client_file_too(tmp_path, monkeypatch):
    """resolve_config, which every scan loads its config through, refuses it:
    the rule is the loader's, not get_config's."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import (
        ASHConfigEnvNotResolvedError,
    )

    monkeypatch.setenv("ASH_X", VALUE)
    config = _delivered(
        tmp_path, monkeypatch, CLIENT_SHAPES["append"].replace("VAR", "ASH_X")
    )

    with pytest.raises(ASHConfigEnvNotResolvedError) as raised:
        resolve_config(
            config_path=config,
            source_dir=config.parent,
            fallback_to_default=False,
            untrusted_config=True,
        )

    assert VALUE not in str(raised.value)
    assert "environment" in str(raised.value)


def test_validate_config_refuses_the_client_file_too(tmp_path, monkeypatch):
    """The check a scan would make, under the same error type: a file the
    validator called valid would be refused by the scan."""
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    monkeypatch.setenv("ASH_X", VALUE)
    config = _delivered(
        tmp_path, monkeypatch, CLIENT_SHAPES["append"].replace("VAR", "ASH_X")
    )

    result = mcp_validate_config(config_path=str(config), session_id="session-a")

    _no_value(result)
    assert result["valid"] is False, result
    assert [e["type"] for e in result["errors"]] == ["config_env_not_resolved"], result


@pytest.mark.parametrize("how", ["named", "discovered"])
def test_the_scan_tool_refuses_the_client_file_before_the_scan_starts(
    tmp_path, monkeypatch, how
):
    """As get_config and validate_config report it, with the code a config the
    scan cannot use exits with, and before a scan is registered: the scan would
    otherwise fail later for the same file, under a generic error."""
    import asyncio

    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.cli.mcp import source_delivery
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    started: List[str] = []

    def record(scan_id, coroutine, **start_options) -> None:
        coroutine.close()
        started.append(scan_id)

    monkeypatch.setattr(mcp_tools, "_start_scan_task", record)
    monkeypatch.setattr(source_delivery, "_SESSION_SOURCE_DIRS", {})
    monkeypatch.setattr(
        scan_registry_module, "_scan_registry", scan_registry_module.ScanRegistry()
    )
    monkeypatch.setenv("ASH_X", VALUE)
    config = _delivered(
        tmp_path, monkeypatch, CLIENT_SHAPES["append"].replace("VAR", "ASH_X")
    )
    (config.parent / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(config.parent))

    result = asyncio.run(
        mcp_tools.mcp_scan_directory(
            directory_path=str(config.parent),
            config_path=str(config) if how == "named" else None,
            session_id="session-a",
        )
    )

    _no_value(result)
    assert result.get("success") is False, result
    assert result["error_type"] == "config_env_not_resolved", result
    assert result["exit_code"] == 3, result
    assert started == []


def test_a_workspace_project_s_refusal_carries_the_same_error_type():
    """The workspace tools re-raise a project's config error with the project
    named, from the original: the refusal keeps its error_type through that."""
    from automated_security_helper.cli.mcp.workspace import _error_response
    from automated_security_helper.core.exceptions import (
        ASHConfigEnvNotResolvedError,
        ASHConfigValidationError,
    )

    try:
        try:
            raise ASHConfigEnvNotResolvedError("projects/a/.ash.yaml reads ...")
        except ASHConfigEnvNotResolvedError as original:
            raise ASHConfigValidationError("project a: ...") from original
    except ASHConfigValidationError as named:
        response = _error_response(named, "scan_workspace")

    assert response["error_type"] == "config_env_not_resolved", response
    assert response["exit_code"] == 3, response


@pytest.mark.parametrize("session_id", ["session-a", None], ids=["remote", "local"])
def test_validate_config_refuses_content_a_remote_client_sent(
    tmp_path, monkeypatch, session_id
):
    """Content a remote client sends is its config too, and is checked in a
    temporary file outside its sandbox: it reads nothing from the environment
    either. The server's own caller (no session) keeps the old reading."""
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    monkeypatch.setenv("ASH_X", VALUE)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))

    result = mcp_validate_config(
        config_content=CLIENT_SHAPES["append"].replace("VAR", "ASH_X"),
        session_id=session_id,
    )

    _no_value(result)
    types = [e["type"] for e in result["errors"]]
    if session_id is None:
        assert "config_env_not_resolved" not in types, result
    else:
        assert result["valid"] is False, result
        assert types == ["config_env_not_resolved"], result
