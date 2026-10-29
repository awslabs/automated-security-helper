# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A refused stop names its tool without the caller's environment values.

A tool's argv0 can carry a value the plugin's config read from the
environment (an option's path, say). The could-not-stop reporting quotes
that argv0: the ``could_not_stop`` record and the ScanCancelled texts in
the cancellable runner, and the "Could not stop"/"Could not kill" WARNING
lines on the stop paths. ``shown_arguments`` rewrites only
``--config-overrides`` values, so argv0 passes through it as it is, and
``run_command``'s own promise -- every line this runner logs is redacted
with the caller's values -- did not reach those lines. These cells plant a
value inside the tool's path and pin that no record, raise text or logged
warning prints it, while a run with no values keeps its tool named as it
is.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess  # nosec B404 - cells spawn the running interpreter, fixed argv
import sys
import threading
import time
from pathlib import Path
from typing import List, Tuple

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core import cancellation
from automated_security_helper.core.cancellation import ScanCancelled, cancel_scope
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.sandbox.scope import uv_record_inputs

PluginContext.model_rebuild()
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="the POSIX stop paths and process groups"
)

#: A marker no fixture path contains, so its absence is the redaction and
#: never an accident of the tmp directory's name.
_SECRET_SEGMENT = "valued-ops-kqj7"


def _tool_inside_a_value(tmp_path: Path) -> Tuple[str, Tuple[str, ...]]:
    """A runnable tool whose argv0 sits inside an environment value.

    The value is the directory's whole path, as a config option holding a
    path reads from the environment; the tool is the running interpreter
    linked under it, so the spawn is real and exits on its own argv.
    """
    valued = tmp_path / _SECRET_SEGMENT
    valued.mkdir()
    tool = valued / "py"
    tool.symlink_to(sys.executable)
    return str(tool), (str(valued),)


@pytest.fixture
def pid_mirror(monkeypatch) -> None:
    """The die-now mirrors start empty, as sigterm_state's comment explains."""
    monkeypatch.setattr(cancellation, "_TOOL_PIDS", ())
    monkeypatch.setattr(cancellation, "_TOOL_GROUPS", ())


@pytest.fixture
def spawned_children(monkeypatch) -> List[subprocess.Popen]:
    """Every child the runner starts, killed and reaped after the cell.

    The refused-stop cells leave their child running by design, and the
    runner's own handle is internal, so the spawn is spied on for the
    cleanup. The group kill matches the runner's own_group spawn; a child
    that led no group is killed by pid.
    """
    children: List[subprocess.Popen] = []
    real_popen = subprocess.Popen

    def popen(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", popen)
    yield children
    for child in children:
        if child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except OSError:
                try:
                    child.kill()
                except OSError:
                    pass
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        # A cell whose _reap timed out left the group recorded; the entry
        # names this test's child, so popping it leaks nothing of anyone
        # else's.
        subprocess_utils._unregister_group(child)


def _could_not_stop_tools(error: ScanCancelled) -> List[str]:
    return [tool for tool, _ in getattr(error, "could_not_stop", ())]


def test_a_kill_refused_at_the_servers_stop_hides_the_commands_value(
    tmp_path, monkeypatch, caplog, pid_mirror, spawned_children
):
    """The server-stop kill refusal: the could_not_stop record, the cancel's
    text and the "Could not kill" warning all hide the value around argv0."""
    tool, values = _tool_inside_a_value(tmp_path)
    # Registered first so the teardown restores it: the wrapper below flips
    # the flag only once the child has started, because a server already
    # stopping refuses the spawn before it (_begin_spawn), which is the
    # was-not-started text and never the refused kill this cell pins.
    monkeypatch.setattr(subprocess_utils, "_STOPPING", False)
    real_note_start = subprocess_utils._note_start

    def stop_once_started(process):
        subprocess_utils._STOPPING = True
        return real_note_start(process)

    monkeypatch.setattr(subprocess_utils, "_note_start", stop_once_started)

    def refuse(process, **kwargs):
        # **kwargs so a future keyword on _kill_group never breaks this stand-in.
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(subprocess_utils, "_kill_group", refuse)

    event = threading.Event()
    with cancel_scope(event):
        with caplog.at_level(logging.WARNING, logger="ash"):
            with pytest.raises(ScanCancelled) as raised:
                subprocess_utils.run_command([tool, "-c", "pass"], values=values)

    message = str(raised.value)
    assert "could not stop" in message, message
    assert _SECRET_SEGMENT not in message, message
    tools = _could_not_stop_tools(raised.value)
    assert tools, "the refusal carried no could_not_stop record"
    assert all(_SECRET_SEGMENT not in tool_name for tool_name in tools), tools
    warnings = [
        record.getMessage()
        for record in caplog.records
        if "Could not kill" in record.getMessage()
    ]
    assert warnings, "the refused kill logged no warning"
    assert all(_SECRET_SEGMENT not in line for line in warnings), warnings


def test_a_refused_cancel_stop_hides_the_commands_value(
    tmp_path, monkeypatch, caplog, pid_mirror, spawned_children
):
    """The cancel path whose stop the kernel refuses: the raise text, the
    record, and the "Could not stop" warnings all hide the value."""
    tool, values = _tool_inside_a_value(tmp_path)
    # The reaping wait after the refused stop is bounded by the test, not
    # the 2 s default; the fixture reaps the survivor.
    monkeypatch.setattr(subprocess_utils, "_REAP_SECONDS", 0.2)

    def refuse(process, grace, prompt=None):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(subprocess_utils, "_stop_tree", refuse)
    monkeypatch.setattr(subprocess_utils, "_stop", refuse)

    marker = tmp_path / "started"
    event = threading.Event()

    def cancel_once_started() -> None:
        while not marker.exists():
            time.sleep(0.01)
        event.set()

    watcher = threading.Thread(target=cancel_once_started, daemon=True)
    watcher.start()
    script = (
        "import pathlib, sys, time\n"
        "pathlib.Path(sys.argv[1]).write_text('started')\n"
        "time.sleep(30)\n"
    )
    with cancel_scope(event):
        with caplog.at_level(logging.WARNING, logger="ash"):
            with pytest.raises(ScanCancelled) as raised:
                subprocess_utils.run_command(
                    [tool, "-c", script, str(marker)], values=values
                )
    watcher.join(timeout=10)

    message = str(raised.value)
    assert "could not stop" in message, message
    assert _SECRET_SEGMENT not in message, message
    tools = _could_not_stop_tools(raised.value)
    assert tools, "the refusal carried no could_not_stop record"
    assert all(_SECRET_SEGMENT not in tool_name for tool_name in tools), tools
    warnings = [
        record.getMessage()
        for record in caplog.records
        if "Could not stop" in record.getMessage()
    ]
    assert warnings, "the refused stop logged no warning"
    assert all(_SECRET_SEGMENT not in line for line in warnings), warnings


class _Config(ScannerPluginConfigBase):
    name: str = "watched"


class _Scanner(ScannerPluginBase):
    tool: str = sys.executable

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("the cell calls _run_subprocess directly")


def _plugin_context(tmp_path) -> PluginContext:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "output"
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=tmp_path / "work",
        config=AshConfig(project_name="test"),
    )


def test_the_recorded_reason_reaches_the_report_without_the_value(
    tmp_path, monkeypatch, pid_mirror, spawned_children
):
    """The record all the way to the publishable artifact: a real refused run's
    response, through the plugin's recorder, holds no value anywhere.

    The runner's response is captured from a real timed-out run whose stop the
    kernel refused (a cancel aborts the scan instead of answering, so the
    timeout is the path that returns the record); the plugin's recorder stores
    its error as ``scan_could_not_stop``, and the executor copies that string
    verbatim onto the result container the aggregated results publish
    (scanner_executor: ``container.could_not_stop = could_not_stop_reason``),
    so the stored reason IS the artifact's text.
    """
    tool, values = _tool_inside_a_value(tmp_path)
    monkeypatch.setattr(subprocess_utils, "_REAP_SECONDS", 0.2)

    def refuse(process, grace=None, prompt=None):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(subprocess_utils, "_stop_tree", refuse)
    monkeypatch.setattr(subprocess_utils, "_stop", refuse)
    monkeypatch.setattr(subprocess_utils, "_kill", refuse)

    results = tmp_path / "results"
    results.mkdir()
    event = threading.Event()
    with cancel_scope(event):
        response = subprocess_utils.run_command_with_output_handling(
            [tool, "-c", "import time; time.sleep(30)"],
            results_dir=results,
            stdout_preference="return",
            stderr_preference="return",
            class_name="watched",
            timeout=0.5,
            values=values,
        )

    # The transport dict's error stays raw by the runner's own rule -- "the
    # returned text is redacted where the caller keeps it" -- so the cell pins
    # the KEPT text below, not the in-memory dict between runner and keeper.
    assert response.get("could_not_stop") is True, response

    class _ValuedScanner(_Scanner):
        """The run's values through the designed hook, as a plugin whose
        config read them from the environment carries them."""

        def _environment_values(self):
            return list(values)

    scanner = _ValuedScanner(config=_Config(), context=_plugin_context(tmp_path))
    scanner.use_uv_tool = False
    monkeypatch.setattr(
        subprocess_utils,
        "run_command_with_output_handling",
        lambda **kwargs: dict(response),
    )
    scanner._run_subprocess(command=[sys.executable, "-c", "pass"])

    reason = scanner.scan_could_not_stop
    assert reason, "the plugin recorded no could-not-stop reason"
    assert _SECRET_SEGMENT not in reason, reason


def test_a_refused_interrupt_stop_logs_without_the_records_values(
    tmp_path, caplog, pid_mirror
):
    """The interrupt stop path has no values parameter; its refusal line is
    still redacted with the dispatch's record-only context, the same union
    every record made under a scanner's run gets."""
    tool, values = _tool_inside_a_value(tmp_path)
    child = subprocess.Popen(  # nosec B603 - the running interpreter, fixed argv
        [tool, "-c", "pass"], stdin=subprocess.DEVNULL
    )
    try:

        def refuse() -> None:
            raise PermissionError(1, "Operation not permitted")

        with caplog.at_level(logging.WARNING, logger="ash"):
            with uv_record_inputs(values, (), ""):
                assert subprocess_utils._send_stop(child, refuse) is False
    finally:
        child.wait(timeout=10)

    warnings = [
        record.getMessage()
        for record in caplog.records
        if "Could not stop" in record.getMessage()
    ]
    assert warnings, "the refused stop logged no warning"
    assert all(_SECRET_SEGMENT not in line for line in warnings), warnings
    assert all(str(child.pid) in line for line in warnings), warnings


def test_a_refused_stop_with_no_values_names_the_tool_as_it_is(
    tmp_path, caplog, pid_mirror
):
    """With no values and no record context there is nothing to hide, and
    the warning keeps naming the tool, so the operator can find it."""
    tool, _ = _tool_inside_a_value(tmp_path)
    child = subprocess.Popen(  # nosec B603 - the running interpreter, fixed argv
        [tool, "-c", "pass"], stdin=subprocess.DEVNULL
    )
    try:

        def refuse() -> None:
            raise PermissionError(1, "Operation not permitted")

        with caplog.at_level(logging.WARNING, logger="ash"):
            assert subprocess_utils._send_stop(child, refuse) is False
    finally:
        child.wait(timeout=10)

    warnings = [
        record.getMessage()
        for record in caplog.records
        if "Could not stop" in record.getMessage()
    ]
    assert warnings, "the refused stop logged no warning"
    assert any(tool in line for line in warnings), warnings
