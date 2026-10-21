# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan's error exit quotes no input a pydantic model refused, wherever it goes.

Why this exists
---------------
The scan's error exits (``run_ash_scan`` single-directory and workspace mode)
build their message from the error they caught, and a run ASH gives up hands
that message to the MCP runner through ``ScanRefusedExit``, which puts it in the
scan's ``error_message`` for a remote client to read; an error ``run_ash_scan``
raises instead reaches the runner's own arm, which writes ``error_message``
from it as well. pydantic's own text for a
ValidationError quotes every refused input (``input_value='...'``), and a config
value can be a secret read from the environment. So each exit is driven with a
ValidationError whose input holds a canary, raised directly and raised from
another error that quotes it, and the canary must be in neither the exit's
message, the client's ``error_message``, the console, nor the log.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Dict

import pytest
from pydantic import BaseModel, ValidationError

from automated_security_helper.core.enums import RunMode
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.interactions import run_ash_scan as run_module

CANARY = "ash-canary-5d1b"


class _Strict(BaseModel):
    """A model that keeps pydantic's default text, which quotes its input."""

    count: int


def _validation_error() -> ValidationError:
    try:
        _Strict(count=CANARY)
    except ValidationError as error:
        return error
    raise AssertionError("the model accepted the canary")


def _direct() -> BaseException:
    return _validation_error()


def _wrapped() -> BaseException:
    """An error raised from a ValidationError, whose message quotes it."""
    error = _validation_error()
    try:
        raise RuntimeError(f"the config did not load: {error}") from error
    except RuntimeError as wrapped:
        return wrapped


ERRORS = {"a ValidationError": _direct, "an error raised from one": _wrapped}


@pytest.fixture(autouse=True)
def _control() -> None:
    """The canary is in pydantic's own text, so its absence below is withheld."""
    assert CANARY in str(_validation_error())
    assert CANARY in str(_wrapped())


@pytest.fixture
def registry(monkeypatch):
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    fresh = scan_registry_module.ScanRegistry()
    monkeypatch.setattr(scan_registry_module, "_scan_registry", fresh)
    return fresh


@pytest.fixture
def tree(tmp_path) -> Dict[str, Path]:
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    return {"source": source, "output": source / ".ash" / "ash_output"}


def _raising(monkeypatch, error: BaseException) -> None:
    def _create(cls, **_kwargs: Any) -> None:
        raise error

    monkeypatch.setattr(ASHScanOrchestrator, "create", classmethod(_create))


def _log_files(output: Path) -> str:
    return "".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name.endswith((".log", ".log.jsonl"))
    )


@pytest.mark.parametrize("make", ERRORS.values(), ids=ERRORS)
def test_the_cli_exit_quotes_no_input(make, tree, monkeypatch, capfd, caplog) -> None:
    _raising(monkeypatch, make())
    caplog.set_level(logging.DEBUG)

    with pytest.raises(SystemExit) as exited:
        run_module.run_ash_scan(
            source_dir=tree["source"],
            output_dir=tree["output"],
            mode=RunMode.local,
            progress=False,
            show_summary=False,
        )
    seen = capfd.readouterr()

    assert exited.value.code == 1
    message = getattr(exited.value, "message", "")
    assert message.startswith("Exiting due to exception during ASH scan: "), message
    # The control: the message still names the field that was refused.
    assert "count" in message, message
    channels = {
        "message": message,
        "stdout": seen.out,
        "stderr": seen.err,
        "log records": caplog.text,
        "log files": _log_files(tree["output"]),
    }
    leaked = [name for name, text in channels.items() if CANARY in text]
    assert leaked == [], (leaked, channels)


def _mcp_progress(registry, tree: Dict[str, Path]) -> Dict[str, Any]:
    """The MCP runner over one scan of the tree, and the progress a client reads."""
    from automated_security_helper.cli import mcp_tools

    tree["output"].mkdir(parents=True)
    scan_id = registry.register_scan(
        directory_path=str(tree["source"]), output_directory=str(tree["output"])
    )

    async def _run() -> Dict[str, Any]:
        await mcp_tools._run_scan_async(
            scan_id=scan_id,
            directory_path=str(tree["source"]),
            output_dir=str(tree["output"]),
            severity_threshold=None,
        )
        return await mcp_tools.mcp_get_scan_progress(scan_id)

    return asyncio.run(_run())


def _told_no_input(progress: Dict[str, Any], caplog) -> None:
    assert progress["status"] == "failed", progress
    assert progress["exit_code"] == 1, progress
    assert "count" in progress["error_message"], progress
    assert CANARY not in progress["error_message"], progress
    assert CANARY not in caplog.text, caplog.text


@pytest.mark.parametrize("make", ERRORS.values(), ids=ERRORS)
def test_the_mcp_client_is_told_no_input(
    make, tree, registry, monkeypatch, caplog
) -> None:
    _raising(monkeypatch, make())
    caplog.set_level(logging.DEBUG)

    _told_no_input(_mcp_progress(registry, tree), caplog)


@pytest.mark.parametrize("make", ERRORS.values(), ids=ERRORS)
def test_an_error_out_of_the_scan_tells_the_mcp_client_no_input(
    make, tree, registry, monkeypatch, caplog
) -> None:
    """run_ash_scan raising, rather than exiting, reaches the runner's own arm."""
    error = make()

    def _raises(**_kwargs: Any) -> None:
        raise error

    monkeypatch.setattr(run_module, "run_ash_scan", _raises)
    caplog.set_level(logging.DEBUG)

    progress = _mcp_progress(registry, tree)

    assert progress["error_message"].startswith("Error executing scan: "), progress
    _told_no_input(progress, caplog)


@pytest.mark.parametrize("make", ERRORS.values(), ids=ERRORS)
def test_the_workspace_exit_quotes_no_input(
    make, tmp_path, monkeypatch, capfd, caplog
) -> None:
    from automated_security_helper.workspace import execution as workspace_execution
    from tests.unit.interactions.test_run_ash_scan_workspace_coverage import _plan

    error = make()

    def _execute(plan, settings) -> None:
        raise error

    monkeypatch.setattr(workspace_execution, "execute_workspace", _execute)
    caplog.set_level(logging.DEBUG)
    opts = run_module.ScanOptions(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        workspace_plan=_plan(tmp_path, "api"),
    )

    with pytest.raises(SystemExit) as exited:
        run_module._run_workspace_mode(opts, logging.getLogger("ash.test.canary"))
    seen = capfd.readouterr()

    assert exited.value.code == 1
    message = getattr(exited.value, "message", "")
    assert "count" in message, message
    channels = {
        "message": message,
        "stdout": seen.out,
        "stderr": seen.err,
        "log records": caplog.text,
    }
    leaked = [name for name, text in channels.items() if CANARY in text]
    assert leaked == [], (leaked, channels)
