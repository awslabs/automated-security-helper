# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""MCP scan_directory checks a named config once, and refuses one that does not validate.

Before a scan is registered, scan_directory checks the config the client named:
that it and every base it extends are inside the session's grant, and that it
loads. The two checks each parsed the file, on the event loop that every
session shares, and the load check never validated the result, so a config the
scan refuses with exit 3 (``global_settings: 7``) started a scan that then
failed, while ``get_config`` refused the same file up front. The run_ash_scan
tool ran the grant check once more before calling scan_directory.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from automated_security_helper.cli.mcp.sandbox import (
    ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV,
    ASH_MCP_ALLOWED_ROOTS_ENV,
    ASH_MCP_TRANSPORT_ENV,
)
from automated_security_helper.config import config_sources


@pytest.fixture
def target(tmp_path, monkeypatch) -> Path:
    monkeypatch.delenv(ASH_MCP_ALLOWED_ROOTS_ENV, raising=False)
    monkeypatch.delenv(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, raising=False)
    monkeypatch.setenv(ASH_MCP_TRANSPORT_ENV, "stdio")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    scan = tmp_path / "scan"
    scan.mkdir()
    (scan / "app.py").write_text("x = 1\n", encoding="utf-8")
    return scan


def _scan(target: Path, config: Path):
    from automated_security_helper.cli.mcp_tools import mcp_scan_directory

    with patch("automated_security_helper.cli.mcp_tools._run_scan_async") as started:
        result = asyncio.run(
            mcp_scan_directory(directory_path=str(target), config_path=str(config))
        )
    return result, started.called


def test_a_config_that_does_not_validate_is_refused_before_the_scan(
    target, monkeypatch
):
    # A config root, so the file is the operator's. A file a client delivered or
    # named outside the config roots that also sets a field a client may not is
    # refused for that field first (test_denial_check_failures.py).
    monkeypatch.setenv(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, str(target))
    config = target / ".ash.yaml"
    config.write_text("global_settings: 7\n", encoding="utf-8")

    result, started = _scan(target, config)

    assert result["success"] is False, result
    assert result["error_category"] == "invalid_format"
    assert "global_settings" in result["error"]
    assert started is False


def _count_reads(monkeypatch) -> List[Path]:
    reads: List[Path] = []
    real_read = config_sources.read_config_file

    def counting_read(path, *args, **kwargs):
        reads.append(Path(path))
        return real_read(path, *args, **kwargs)

    monkeypatch.setattr(config_sources, "read_config_file", counting_read)
    return reads


def test_the_config_is_parsed_once(target, monkeypatch):
    config = target / ".ash.yaml"
    config.write_text("project_name: once\n", encoding="utf-8")
    reads = _count_reads(monkeypatch)

    result, started = _scan(target, config)

    assert result["success"] is True, result
    assert started is True
    assert reads.count(config) == 1, reads


def test_run_ash_scan_parses_the_config_once(target, monkeypatch):
    """run_ash_scan checks a named config before it acts on the target, and
    hands the result to scan_directory instead of having it read the file
    again."""
    from automated_security_helper.cli import mcp_server

    async def _no_monitor(*args, **kwargs):
        return None

    monkeypatch.setattr(mcp_server, "monitor_scan_progress", _no_monitor)
    ctx = MagicMock()
    for method in ("info", "error", "warning", "debug", "report_progress"):
        setattr(ctx, method, AsyncMock())
    config = target / ".ash.yaml"
    config.write_text("project_name: once\n", encoding="utf-8")
    reads = _count_reads(monkeypatch)

    with patch("automated_security_helper.cli.mcp_tools._run_scan_async") as started:
        result = asyncio.run(
            mcp_server.run_ash_scan(
                ctx=ctx, source_dir=str(target), config_path=str(config)
            )
        )

    assert result["success"] is True, result
    assert started.called
    assert reads.count(config) == 1, reads


def _raise(error: BaseException):
    def raiser(*args, **kwargs):
        raise error

    return raiser


def test_a_rust_panic_while_validating_is_refused_before_the_scan(target, monkeypatch):
    """pydantic-core reports a Rust panic as pyo3's PanicException, a
    BaseException; it is refused as a config that does not load, as the scan's
    own resolution refuses it, instead of reaching the event loop."""
    from automated_security_helper.config.ash_config import AshConfig

    panic = type("PanicException", (BaseException,), {"__module__": "pyo3_runtime"})
    monkeypatch.setattr(
        AshConfig, "model_validate", _raise(panic("PyObject pointer is null"))
    )
    config = target / ".ash.yaml"
    config.write_text("project_name: x\n", encoding="utf-8")

    result, started = _scan(target, config)

    assert result["success"] is False, result
    assert result["error_category"] == "invalid_format"
    assert "PanicException" in result["error"]
    assert started is False


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit])
def test_control_an_interrupt_still_propagates(target, monkeypatch, error):
    from automated_security_helper.config.ash_config import AshConfig

    monkeypatch.setattr(AshConfig, "model_validate", _raise(error()))
    config = target / ".ash.yaml"
    config.write_text("project_name: x\n", encoding="utf-8")

    with pytest.raises(error):
        _scan(target, config)


def test_control_a_valid_config_starts_the_scan(target):
    config = target / ".ash.yaml"
    config.write_text("project_name: fine\n", encoding="utf-8")

    result, started = _scan(target, config)

    assert result["success"] is True, result
    assert started is True


# ---------------------------------------------------------------------------
# A client's file that does not validate: refused without its values
# ---------------------------------------------------------------------------

CANARY = "CANARY-VALUE-7f3a"
#: Invalid at a field a client's file may set (an ignore path's ``path`` must be a
#: string), so no denied-fields refusal comes first.
INVALID_AT_AN_ALLOWED_FIELD = (
    f"global_settings:\n  ignore_paths:\n    - path: [{CANARY}]\n      reason: r\n"
)


def _no_canary_anywhere(error: BaseException) -> None:
    """Not in the message, the arguments, or any exception it was raised from."""
    seen = set()
    current: Any = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        assert CANARY not in str(current), current
        assert CANARY not in repr(current.args), current.args
        assert current.__cause__ is None or id(current.__cause__) not in seen
        current = current.__cause__ or current.__context__


def test_a_client_named_file_that_does_not_validate_quotes_no_value(target, caplog):
    """The client-path counterpart of the test above: named outside every config
    root, the file is the client's, and the refusal says where each problem is
    without the value it found there."""
    import logging

    config = target / ".ash.yaml"
    config.write_text(INVALID_AT_AN_ALLOWED_FIELD, encoding="utf-8")

    with caplog.at_level(logging.DEBUG):
        result, started = _scan(target, config)

    assert result["success"] is False, result
    assert result["error_category"] == "invalid_format", result
    assert "ignore_paths" in result["error"], result
    assert CANARY not in repr(result)
    assert CANARY not in caplog.text
    assert started is False


@pytest.mark.parametrize("source", ["client", "repository", "operator"])
def test_the_load_check_repeats_no_value_it_found(
    target, tmp_path, monkeypatch, source
):
    """check_config_input's result gives no value it found: for a file the client
    named outside the config roots, for one in the scanned directory, and for an
    operator's file in a config root outside the tree. The operator's keeps
    pydantic's text, which names the field and the problem but not the input."""
    from automated_security_helper.cli.mcp.sandbox import check_config_input

    if source == "client":
        config = target / ".ash.yaml"
    elif source == "repository":
        monkeypatch.setenv(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, str(target))
        config = target / ".ash.yaml"
    else:
        ops = tmp_path / "ops"
        ops.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, str(ops))
        config = ops / "ash.yaml"
    config.write_text(INVALID_AT_AN_ALLOWED_FIELD, encoding="utf-8")

    checked = check_config_input(str(config), source_dir=target)

    assert checked.load_error is not None
    _no_canary_anywhere(checked.load_error)
    assert "ignore_paths" in str(checked.load_error)
    if source == "operator":
        assert "validation error for AshConfig" in str(checked.load_error)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(INVALID_AT_AN_ALLOWED_FIELD, id="does-not-validate"),
        pytest.param(f"project_name: [{CANARY}\n  : :\n", id="does-not-parse"),
    ],
)
def test_the_unquoted_errors_hold_no_value_in_their_cause_or_context(target, text):
    """Raised with no cause, and outside the handler, so no context either."""
    from automated_security_helper.config.resolve_config import (
        CLIENT_FILE,
        read_config_document,
        validate_config_document,
    )

    config = target / ".ash.yaml"
    config.write_text(text, encoding="utf-8")

    with pytest.raises(Exception) as raised:
        validate_config_document(
            read_config_document(config, unquoted=True), config, unquoted=CLIENT_FILE
        )

    _no_canary_anywhere(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_run_ash_scan_refuses_an_invalid_file_for_its_denied_field_first(
    target, monkeypatch
):
    """The run_ash_scan route: the denial names what to remove, as on scan_directory."""
    from automated_security_helper.cli import mcp_server

    async def _no_monitor(*args, **kwargs):
        return None

    monkeypatch.setattr(mcp_server, "monitor_scan_progress", _no_monitor)
    ctx = MagicMock()
    for method in ("info", "error", "warning", "debug", "report_progress"):
        setattr(ctx, method, AsyncMock())
    config = target / ".ash.yaml"
    config.write_text(
        "fail_on_findings: false\nash_plugin_modules: 5\n", encoding="utf-8"
    )

    with patch("automated_security_helper.cli.mcp_tools._run_scan_async") as started:
        result = asyncio.run(
            mcp_server.run_ash_scan(
                ctx=ctx, source_dir=str(target), config_path=str(config)
            )
        )

    assert result.get("error_type") == "config_field_denied", result
    assert not started.called


@pytest.mark.parametrize(
    "failure",
    ["cannot finish", "policy unreadable"],
)
def test_a_denial_check_without_a_denial_leaves_the_load_error(
    target, monkeypatch, failure
):
    """For a file that does not validate: a check that cannot finish leaves the
    load error to report; a policy that cannot be read is reported first, as a
    denied field is."""
    from automated_security_helper.config import client_config_policy
    from automated_security_helper.core.exceptions import (
        ASHConfigPolicyUnreadableError,
    )

    error = (
        RuntimeError("check broke")
        if failure == "cannot finish"
        else ASHConfigPolicyUnreadableError("the policy could not be read")
    )
    monkeypatch.setattr(client_config_policy, "client_file_denials", _raise(error))
    config = target / ".ash.yaml"
    config.write_text(INVALID_AT_AN_ALLOWED_FIELD, encoding="utf-8")

    result, started = _scan(target, config)

    assert started is False
    if failure == "cannot finish":
        assert result.get("error_category") == "invalid_format", result
    else:
        assert result.get("error_type") == "config_policy_unreadable", result
