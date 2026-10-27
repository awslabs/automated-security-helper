# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config path that is not a regular file is refused before it is opened.

Opening a FIFO for reading waits for a writer, so a FIFO named as the config
(``--config``, or ``ASH_CONFIG``, which is ``--config``'s environment variable)
left ``ash config validate``, ``lint`` and ``get`` waiting for ever, and so did a
container-mode scan, whose sandbox probe reads ASH_CONFIG's chain
(``get_default_config``). A character device such as ``/dev/null`` was read as
an empty config. ``config_sources.refuse_unless_a_file`` refuses every such path
with stat, without opening it, for each reader and the root of every chain, and
the commands exit 3, as they do for a config a scan refuses.

The commands and functions that edit a config file open it too, ``init --force``
for writing, and waited the same way: ``config update``, the wizard (with
``--config`` and with ASH_CONFIG), ``init --force``, the inspect app's
``add_suppression_to_config`` (YAML and JSON), the MCP ``get_config`` tool with
``raw``, ``ConfigLinter.fix`` and ``fix_unused_suppressions``, and
``ConfigValidator.check_config_file`` given contents read already. Each refuses
the path with the same check, the commands with exit 3, within
``_OPENER_WAIT`` seconds.

/dev/zero is refused by the same check, but no cell reads it: without the
check, reading it never ends, and the cell would fill memory instead of failing.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any, Callable, List, Optional

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.skipif(
    not hasattr(os, "mkfifo"), reason="a FIFO needs os.mkfifo"
)

#: Long enough for a refusal on a loaded host, short against "for ever".
_WAIT = 20

#: The bound for the commands and functions that edit a config file: the
#: refusal is one stat call.
_OPENER_WAIT = 5


def _release(fifo: Optional[Path]) -> List[int]:
    """Let a caller blocked in open() on *fifo* go on: a reader, by opening its
    write end, and a writer, by opening its read end. Both non-blocking, so
    neither waits. Returns the descriptors, to close once the caller is done:
    a read end closed at once would fail the writer's write instead."""
    if fifo is None:
        return []
    fds = []
    for flags in (os.O_RDONLY | os.O_NONBLOCK, os.O_WRONLY | os.O_NONBLOCK):
        try:
            fds.append(os.open(fifo, flags))
        except OSError:
            pass
    return fds


def _within(
    call: Callable[[], Any], fifo: Optional[Path] = None, wait: float = _WAIT
) -> Any:
    """*call*'s result, failing the test if it has not returned in *wait* seconds."""
    box: dict = {}

    def run() -> None:
        try:
            box["value"] = call()
        except BaseException as error:  # handed to the test below
            box["error"] = error

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(wait)
    if thread.is_alive():
        fds = _release(fifo)
        thread.join(_WAIT)
        for fd in fds:
            os.close(fd)
        pytest.fail(f"still waiting after {wait} s: the config was opened")
    if "error" in box:
        raise box["error"]
    return box["value"]


@pytest.fixture
def fifo(tmp_path) -> Path:
    path = tmp_path / "ash.yaml"
    os.mkfifo(path)
    return path


@pytest.mark.parametrize("command", ["validate", "lint", "get"])
def test_a_fifo_ash_config_is_refused_without_waiting(
    tmp_path, monkeypatch, fifo, command
):
    monkeypatch.setenv("ASH_CONFIG", str(fifo))
    monkeypatch.chdir(tmp_path)

    result = _within(lambda: CliRunner().invoke(app, ["config", command]), fifo)

    assert result.exit_code == 3, result.output
    assert "is not a regular file" in result.output, result.output


@pytest.mark.parametrize("command", ["validate", "lint"])
def test_a_fifo_named_with_config_is_refused_without_waiting(
    tmp_path, monkeypatch, fifo, command
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)

    result = _within(
        lambda: CliRunner().invoke(app, ["config", command, "--config", str(fifo)]),
        fifo,
    )

    assert result.exit_code == 3, result.output
    assert "is not a regular file" in result.output, result.output


def test_a_device_is_not_read_as_an_empty_config(tmp_path, monkeypatch):
    if not Path("/dev/null").exists():
        pytest.skip("no /dev/null")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(app, ["config", "validate", "--config", "/dev/null"])

    assert result.exit_code == 3, result.output
    assert "is not a regular file" in result.output, result.output


def test_the_default_load_refuses_a_fifo(monkeypatch, fifo):
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    monkeypatch.setenv("ASH_CONFIG", str(fifo))

    with pytest.raises(ASHConfigValidationError, match="is not a file"):
        _within(get_default_config, fifo)


def test_the_container_sandbox_probe_returns(tmp_path, monkeypatch, fifo):
    """The probe a container-mode scan runs first reads ASH_CONFIG's chain; one
    that does not load sets no floor, so the mode is the defaults'."""
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions import run_ash_scan

    monkeypatch.setenv("ASH_CONFIG", str(fifo))
    opts = run_ash_scan.ScanOptions(
        source_dir=tmp_path, output_dir=tmp_path / "out", mode=RunMode.container
    )

    modes = _within(lambda: run_ash_scan._sandbox_modes_requested(opts), fifo)

    assert isinstance(modes, list), modes


@pytest.mark.parametrize(
    "named_by",
    ["--config", "ASH_CONFIG"],
)
@pytest.mark.parametrize(
    "command",
    [
        ["update", "--set", "global_settings.severity_threshold=LOW"],
        ["wizard"],
        ["init", "--force"],
    ],
    ids=["update", "wizard", "init-force"],
)
def test_a_command_that_edits_the_config_refuses_a_fifo(
    tmp_path, monkeypatch, fifo, command, named_by
):
    monkeypatch.chdir(tmp_path)
    if named_by == "ASH_CONFIG":
        monkeypatch.setenv("ASH_CONFIG", str(fifo))
        args = command
    else:
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        args = [*command, "--config", str(fifo)]

    # Every prompt the wizard would ask takes its default.
    result = _within(
        lambda: CliRunner().invoke(app, ["config", *args], input="\n" * 50),
        fifo,
        _OPENER_WAIT,
    )

    assert result.exit_code == 3, result.output
    assert "is not a regular file" in result.output, result.output
    assert fifo.exists() and not fifo.is_file(), "the FIFO was replaced"


@pytest.mark.parametrize("name", ["ash.yaml", "ash.json"])
def test_add_suppression_refuses_a_fifo(tmp_path, name):
    """The save's refusal, not the readers' raw one: the shared check's words
    arrive wrapped in the save's own form, a ValueError ending with the path
    and that it is unchanged, as every refusal of the save does."""
    from automated_security_helper.config.ash_config import add_suppression_to_config
    from automated_security_helper.models.core import AshSuppression

    path = tmp_path / name
    os.mkfifo(path)
    suppression = AshSuppression(rule_id="R1", path="src/a.py", reason="r")

    with pytest.raises(ValueError, match="is not a regular file") as refused:
        _within(
            lambda: add_suppression_to_config(path, suppression), path, _OPENER_WAIT
        )

    assert str(refused.value).endswith(f"{path} is unchanged"), refused.value


@pytest.mark.parametrize("kind", ["fifo", "directory"])
def test_mcp_get_config_raw_refuses_what_is_not_a_file(tmp_path, kind):
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    path = tmp_path / "ash.yaml"
    if kind == "fifo":
        os.mkfifo(path)
    else:
        path.mkdir()

    result = _within(
        lambda: mcp_get_config(config_path=str(path), raw=True), path, _OPENER_WAIT
    )

    assert result.get("success") is False, result
    assert "is not a regular file" in result.get("error", ""), result


@pytest.mark.parametrize("method", ["fix", "fix_unused_suppressions"])
def test_the_linter_s_fixers_refuse_a_fifo(fifo, method):
    from automated_security_helper.config.config_linter import ConfigLinter
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    with pytest.raises(ASHConfigSourceError, match="is not a regular file"):
        _within(lambda: getattr(ConfigLinter, method)(fifo), fifo, _OPENER_WAIT)


def test_a_check_given_the_contents_refuses_a_fifo(fifo):
    """The caller read the file already (the linter passes what it read): the
    check reads its text once more for the duplicate-key check."""
    from automated_security_helper.config.config_validator import ConfigValidator

    check = _within(
        lambda: ConfigValidator.check_config_file(
            fifo, config_data={"project_name": "t"}
        ),
        fifo,
        _OPENER_WAIT,
    )

    assert any("is not a regular file" in error for error in check.errors), check


def test_a_regular_file_is_read(tmp_path, monkeypatch):
    """Control: the check refuses only what is not a regular file."""
    config = tmp_path / "ash.yaml"
    config.write_text("project_name: t\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(config))
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(app, ["config", "validate"])

    assert result.exit_code == 0, result.output
