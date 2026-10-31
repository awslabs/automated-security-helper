# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Inputs and endings at the edges of what the jupyter converter handles.

- A notebook was read, decoded and parsed whole with no bound, so one very large
  file could take the scan's memory; one over the bound is now an input error.
- A deeply nested JSON file named .ipynb raised RecursionError out of the parse
  and was recorded as a tool failure, which no suppression accepts.
- A jupyter-nbconvert installed through uv made the converter ready on the
  install alone, with no version read under the converter's requirement.
- An ImportError from the uv runner import became UnboundLocalError at the
  except clause that names the runner's error type.
- uv's own diagnostics, which quote the resolved requirement, were logged as is.
- A timeout whose stop did not end nbconvert was recorded as a plain timeout.
- A file that is not a notebook counted as a candidate for the completeness gate,
  though convert() never hands one to nbconvert.
- A JSON null ``file_extension`` was kept in the copy, and a notebook naming its
  language only in its kernelspec, or as ``python3``, got the wrong exporter.
- On the direct route an OSError after nbconvert started was recorded as a failed
  start, and a signal death as an exit code.
- A notebook the sandbox refused was recorded twice, as refused and as failed.
- Log lines quoting the notebook's path were rendered as markup.
- Both converters walked the tree without the workspace's output directory.
"""

from __future__ import annotations

import errno
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
    JupyterConverter,
    JupyterConverterConfig,
    _FoundNbconvert,
    _parse_notebook,
)
from automated_security_helper.utils import uv_tool_runner
from automated_security_helper.utils.log import NO_MARKUP
from automated_security_helper.utils.subprocess_utils import (
    SpawnFailedProcess,
    TimedOutProcess,
    could_not_stop_sentence,
    signal_ending,
)
from tests.unit.converters.nbconvert_routes import use_stand_in_nbconvert
from tests.utils.process_guard import refuse_process_starts

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("no_tool_probes")]

MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter"
)

NOTEBOOK = {
    "cells": [
        {"cell_type": "code", "metadata": {}, "outputs": [], "source": ["x = 1\n"]}
    ],
    "metadata": {"language_info": {"name": "python"}},
    "nbformat": 4,
    "nbformat_minor": 4,
}


@pytest.fixture
def converter(test_plugin_context):
    test_plugin_context.run_id = "d" * 32
    return JupyterConverter(
        context=test_plugin_context, config=JupyterConverterConfig()
    )


@pytest.fixture
def ash_log_records():
    """Records of the 'ash' logger at DEBUG and above (its level is forced; it
    does not propagate, so caplog never sees it)."""
    records: list[logging.LogRecord] = []

    class _Collector(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collector(level=logging.DEBUG)
    logger = logging.getLogger("ash")
    previous = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous)


def _notebook_in(context, name: str, content: bytes) -> Path:
    tree = Path(context.source_dir)
    tree.mkdir(parents=True, exist_ok=True)
    path = tree / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def _scan_set_of(monkeypatch, *paths: Path) -> None:
    monkeypatch.setattr(
        f"{MODULE}.scan_set", lambda **kwargs: [str(path) for path in paths]
    )


def _uv_runner_returning(monkeypatch, result) -> Mock:
    runner = Mock()
    runner.is_uv_available.return_value = True
    runner.unavailable_reason.return_value = "uv is not installed"
    runner.run_tool.return_value = result
    monkeypatch.setattr(uv_tool_runner, "get_uv_tool_runner", lambda: runner)
    return runner


# ---------------------------------------------------------------- read bound


def test_a_notebook_over_the_read_bound_is_an_input_error(
    converter, monkeypatch, test_plugin_context
):
    monkeypatch.setattr(f"{MODULE}._NOTEBOOK_MAX_BYTES", 64, raising=True)
    big = _notebook_in(
        test_plugin_context, "big.ipynb", json.dumps(NOTEBOOK).encode() + b" " * 200
    )
    _scan_set_of(monkeypatch, big)
    use_stand_in_nbconvert(monkeypatch, converter)
    started = refuse_process_starts(monkeypatch)
    monkeypatch.setattr(f"{MODULE}.run_ended_with_the_server", started.append)

    results = converter.convert()

    assert results == []
    (failed,) = converter.failed_inputs
    assert failed.kind == "input"
    assert "larger than 64 bytes" in failed.reason
    assert started == []


def test_deeply_nested_json_is_an_input_error():
    parsed, problem = _parse_notebook(b"[" * 100_000 + b"]" * 100_000)

    assert parsed is None
    assert problem == "its JSON is nested too deeply to read"


# ---------------------------------------------------------------- uv readiness


def _uv_install_only(monkeypatch, uv_version):
    monkeypatch.setattr(
        JupyterConverter,
        "_get_tool_installation_info",
        lambda self: {
            "available": True,
            "preferred_source": "uv",
            "is_uv_installed": True,
            "is_pre_installed": False,
            "uv_version": uv_version,
            "pre_installed_path": None,
        },
    )
    monkeypatch.setattr(
        JupyterConverter, "_install_uv_tool", lambda self, timeout=None: False
    )
    monkeypatch.setattr(
        JupyterConverter,
        "_verified_direct_nbconvert",
        lambda self, executable=None: _FoundNbconvert(
            None,
            "no jupyter-nbconvert was found",
            "no jupyter-nbconvert was found",
            None,
        ),
    )
    monkeypatch.setattr(JupyterConverter, "candidate_input_count", lambda self: 1)
    monkeypatch.setattr(f"{MODULE}.sandbox_requested", lambda context: False)


def test_a_uv_install_whose_version_cannot_be_read_is_not_taken_as_ready(
    converter, monkeypatch
):
    _uv_install_only(monkeypatch, uv_version=None)

    assert converter.validate_plugin_dependencies() is False
    assert converter._nbconvert_route is None
    assert converter.dependency_unavailable_reason == "no jupyter-nbconvert was found"


def test_a_uv_install_whose_version_reads_is_ready(converter, monkeypatch):
    """The control: a version read under the requirement is the uv route."""
    _uv_install_only(monkeypatch, uv_version="7.16.6")

    assert converter.validate_plugin_dependencies() is True
    assert converter._nbconvert_route == "uv"


# ---------------------------------------------------------------- uv route endings


def test_an_import_error_of_the_runner_module_is_a_false(
    converter, monkeypatch, tmp_path
):
    monkeypatch.setitem(
        sys.modules, "automated_security_helper.utils.uv_tool_runner", None
    )

    assert (
        converter._execute_nbconvert_via_uv(
            ["jupyter", "nbconvert", "x.ipynb"], cwd=tmp_path
        )
        is False
    )


SECRET = "s3cr3t-constraint-value"


@pytest.mark.parametrize(
    "result",
    [
        pytest.param(
            SpawnFailedProcess(
                ["uv"], 127, "", f"uv: cannot start for nbconvert=={SECRET}", error="x"
            ),
            id="spawn-failed",
        ),
        pytest.param(
            subprocess.CompletedProcess(
                ["uv"], 2, "", f"error: No solution found for nbconvert=={SECRET}"
            ),
            id="uv-error",
        ),
    ],
)
def test_uv_stderr_is_redacted_before_it_is_logged(
    converter, monkeypatch, tmp_path, ash_log_records, result
):
    monkeypatch.setattr(JupyterConverter, "_values_to_redact", lambda self: (SECRET,))
    _uv_runner_returning(monkeypatch, result)

    assert (
        converter._execute_nbconvert_via_uv(
            ["jupyter", "nbconvert", "x.ipynb"], cwd=tmp_path
        )
        is False
    )

    warnings = [r.getMessage() for r in ash_log_records if r.levelno >= logging.WARNING]
    assert any("uv could not" in message for message in warnings), warnings
    assert not any(SECRET in message for message in warnings), warnings


def test_a_timeout_whose_stop_did_not_end_nbconvert_says_so(
    converter, monkeypatch, test_plugin_context
):
    notebook = _notebook_in(
        test_plugin_context, "nb.ipynb", json.dumps(NOTEBOOK).encode()
    )
    _scan_set_of(monkeypatch, notebook)
    timed_out = TimedOutProcess(["uv"], None, "", "", error="timed out")
    timed_out.could_not_stop = True
    timed_out.could_not_stop_pid = 4242
    _uv_runner_returning(monkeypatch, timed_out)
    monkeypatch.setattr(f"{MODULE}.sandbox_requested", lambda context: False)
    converter._nbconvert_route = "uv"
    refuse_process_starts(monkeypatch)

    results = converter.convert()

    assert results == []
    (failed,) = converter.failed_inputs
    assert "did not finish within 60s" in failed.reason
    assert could_not_stop_sentence("nbconvert (pid 4242)") in failed.reason


# ---------------------------------------------------------------- candidates


def test_a_file_that_is_not_a_notebook_is_not_a_candidate(
    converter, monkeypatch, test_plugin_context
):
    stub = _notebook_in(test_plugin_context, "stub.ipynb", b"not json")
    real = _notebook_in(
        test_plugin_context, "real.ipynb", json.dumps(NOTEBOOK).encode()
    )
    _scan_set_of(monkeypatch, stub, real)

    assert converter.candidate_input_count() == 1


# ---------------------------------------------------------------- staging


def _staged(tmp_path, notebook: dict) -> tuple[str, dict]:
    staged = tmp_path / "notebook.ipynb"
    exporter = JupyterConverter._stage_notebook(
        json.dumps(notebook).encode("utf-8"), staged
    )
    return exporter, json.loads(staged.read_text(encoding="utf-8"))


def test_a_null_file_extension_is_removed_from_the_copy(tmp_path):
    notebook = {
        **NOTEBOOK,
        "metadata": {"language_info": {"name": "r", "file_extension": None}},
    }

    exporter, written = _staged(tmp_path, notebook)

    assert exporter == "script"
    assert "file_extension" not in written["metadata"]["language_info"]


def test_the_kernelspec_language_chooses_the_exporter(tmp_path):
    notebook = {**NOTEBOOK, "metadata": {"kernelspec": {"language": "R", "name": "ir"}}}

    exporter, _ = _staged(tmp_path, notebook)

    assert exporter == "script"


def test_a_python_variant_language_name_keeps_the_python_exporter(tmp_path):
    notebook = {**NOTEBOOK, "metadata": {"language_info": {"name": "python3"}}}

    exporter, _ = _staged(tmp_path, notebook)

    assert exporter == "python"


# ---------------------------------------------------------------- direct route endings


def _direct_run(converter, monkeypatch, test_plugin_context, run):
    notebook = _notebook_in(
        test_plugin_context, "nb.ipynb", json.dumps(NOTEBOOK).encode()
    )
    _scan_set_of(monkeypatch, notebook)
    use_stand_in_nbconvert(monkeypatch, converter)
    refuse_process_starts(monkeypatch)
    monkeypatch.setattr(f"{MODULE}.run_ended_with_the_server", run)
    results = converter.convert()
    assert results == []
    (failed,) = converter.failed_inputs
    return failed.reason


@pytest.mark.skipif(os.name == "nt", reason="Windows has no signal deaths")
def test_a_signal_death_is_named_as_a_signal(
    converter, monkeypatch, test_plugin_context
):
    def killed(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, -9, "", "")

    reason = _direct_run(converter, monkeypatch, test_plugin_context, killed)

    assert reason == signal_ending(-9, "nbconvert")[1]
    assert "exited with code" not in reason


def test_an_os_error_after_the_launch_is_not_called_a_failed_start(
    converter, monkeypatch, test_plugin_context
):
    def failing_run(cmd, **kwargs):
        raise OSError(errno.EIO, "Input/output error")

    reason = _direct_run(converter, monkeypatch, test_plugin_context, failing_run)

    assert reason == "the run of nbconvert failed: Input/output error"


def test_a_launch_the_os_refused_is_a_failed_start(
    converter, monkeypatch, test_plugin_context
):
    """The control: a missing program is still a start that failed."""

    def missing(cmd, **kwargs):
        raise FileNotFoundError(errno.ENOENT, "No such file or directory")

    reason = _direct_run(converter, monkeypatch, test_plugin_context, missing)

    assert reason == "nbconvert could not be started: No such file or directory"


# ---------------------------------------------------------------- one record


def test_an_unconfinable_notebook_is_recorded_once(converter, test_plugin_context):
    notebook = _notebook_in(
        test_plugin_context, "nb.ipynb", json.dumps(NOTEBOOK).encode()
    )

    converter._refuse_unconfinable(
        str(notebook), "bwrap: cannot create a user namespace"
    )

    assert converter.refused_inputs == []
    (failed,) = converter.failed_inputs
    assert failed.path == "nb.ipynb"
    assert "the scanner sandbox refused it" in failed.reason


# ---------------------------------------------------------------- log markup


def test_log_lines_quoting_the_notebook_path_carry_no_markup(
    converter, monkeypatch, test_plugin_context, ash_log_records
):
    stub = _notebook_in(test_plugin_context, "[x]/nb.ipynb", b"not json")
    _scan_set_of(monkeypatch, stub)
    use_stand_in_nbconvert(monkeypatch, converter)
    refuse_process_starts(monkeypatch)

    converter.convert()

    quoting = [r for r in ash_log_records if "nb.ipynb" in r.getMessage()]
    assert quoting, [r.getMessage() for r in ash_log_records]
    without = [
        r.getMessage()
        for r in quoting
        if any(getattr(r, key, None) != value for key, value in NO_MARKUP.items())
    ]
    assert without == []


# ---------------------------------------------------------------- workspace output


def test_the_scan_set_leaves_out_the_workspace_output_directory(
    test_plugin_context, monkeypatch
):
    seen = {}

    def fake_scan_set(**kwargs):
        seen.update(kwargs)
        return []

    monkeypatch.setattr(f"{MODULE}.scan_set", fake_scan_set)
    context = PluginContext(
        source_dir=test_plugin_context.source_dir,
        output_dir=test_plugin_context.output_dir,
        work_dir=test_plugin_context.work_dir,
        config=test_plugin_context.config,
        workspace_output_dir=Path(test_plugin_context.output_dir).parent / "ws-out",
    )
    converter = JupyterConverter(context=context, config=JupyterConverterConfig())

    assert converter._notebooks_in_scan_set() == []
    assert seen["workspace_output_dir"] == str(context.workspace_output_dir)
