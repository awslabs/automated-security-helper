# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every timeout text picks its ending from one predicate and one string pair.

A timeout whose stop worked says the tool "was killed"; one whose stop failed
says ASH could not stop it and it may still be running. Five sites write that
ending: the plugin's own timeout line, the cdk-nag worker's reason, the
template scan's error, and the executor's failed-scan lead and per-target line.
They agreed only because each tested the response, or read the state recorded
from it, in its own way. ``subprocess_utils.response_could_not_stop`` is the
one test, ``COULD_NOT_STOP_ENDING`` and ``WAS_KILLED_ENDING`` are the one pair
of strings, and the recorded state is set through the same test.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)
from automated_security_helper.utils import cdk_nag_worker, subprocess_utils
from tests.unit.base.test_a_could_not_stop_reason_names_the_pid import (
    _uv_scanner_whose_runner_returns,
)
from tests.unit.core.phases.test_a_timeout_ash_could_not_stop_is_never_said_killed import (
    _executor_lines,
    _row,
)
from tests.unit.utils.test_cdk_nag_worker import (
    NOT_CFN,
    _call,
    _fake_child,
    _patch_spawn,
    _templates,
)

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()

_BASE = {
    "stdout": "",
    "stderr": "",
    "timed_out": True,
    "error": "Command timed out after 5s: tool",
}

#: Response shapes of a timed-out run, and whether the stop failed. The first
#: sets the flag and also carries an exit code; the second carries no flag and
#: no exit code; the third is a stop that worked.
_SHAPES = [
    pytest.param(
        {"could_not_stop": True, "could_not_stop_pid": 4242, "returncode": 124},
        True,
        id="flag-with-a-code",
    ),
    pytest.param({"returncode": None}, True, id="no-flag-no-code"),
    pytest.param({"returncode": 124}, False, id="stopped"),
]


def _shared():
    """The shared strings, read when a cell runs so a missing name fails that
    cell alone."""
    return subprocess_utils.COULD_NOT_STOP_ENDING, subprocess_utils.WAS_KILLED_ENDING


def _picks(text: str, stop_failed: bool) -> None:
    could_not_stop, killed = _shared()
    wanted, other = (
        (could_not_stop, killed) if stop_failed else (killed, could_not_stop)
    )
    assert wanted in text, text
    assert other not in text, text


@pytest.mark.parametrize("extra, stop_failed", _SHAPES)
def test_the_predicate_reads_the_recorded_signals(extra, stop_failed):
    response = {**_BASE, **extra}

    assert subprocess_utils.response_could_not_stop(response) is stop_failed


@pytest.mark.parametrize(
    "response",
    [
        pytest.param({"returncode": None}, id="not-timed-out"),
        pytest.param({"returncode": None, "timed_out": False}, id="timed-out-false"),
        pytest.param({"timed_out": True, "returncode": 0}, id="clean-code"),
        pytest.param({"could_not_stop": "yes", "returncode": 1}, id="not-a-bool"),
    ],
)
def test_the_predicate_is_false_for_everything_else(response):
    assert subprocess_utils.response_could_not_stop(response) is False


@pytest.fixture
def checkov(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    output = tmp_path / "out"
    output.mkdir()
    context = PluginContext(source_dir=source, output_dir=output, config=AshConfig())
    scanner = CheckovScanner(
        context=context,
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(scan_timeout=5)
        ),
    )
    scanner.dependencies_satisfied = True
    scanner.use_uv_tool = False
    return scanner, source


@pytest.mark.parametrize("extra, stop_failed", _SHAPES)
def test_the_plugin_timeout_line(checkov, extra, stop_failed):
    scanner, _ = checkov
    with patch.object(CheckovScanner, "_plugin_log") as log:
        scanner._record_timeout({**_BASE, **extra}, 5)

    _picks(log.call_args.args[0], stop_failed)


@pytest.mark.parametrize("extra, stop_failed", _SHAPES)
def test_the_template_scan_error(checkov, extra, stop_failed):
    scanner, source = checkov
    with (
        patch.object(CheckovScanner, "validate_plugin_dependencies", return_value=True),
        patch.object(
            subprocess_utils,
            "run_command_with_output_handling",
            return_value={**_BASE, **extra},
        ),
        pytest.raises(ScannerError) as raised,
    ):
        scanner.scan(target=source, target_type="source")

    _picks(str(raised.value), stop_failed)


@pytest.mark.parametrize("after_run", ["raise", "return"])
@pytest.mark.parametrize("extra, stop_failed", _SHAPES)
def test_the_executor_lead_and_per_target_line(
    tmp_path, monkeypatch, extra, stop_failed, after_run
):
    row = _row(tmp_path, monkeypatch, {**_BASE, **extra}, after_run=after_run)

    lines = _executor_lines(row)
    assert lines, "the executor wrote no timeout line, so the cell shows nothing"
    for line in lines:
        _picks(line, stop_failed)


@pytest.mark.parametrize("extra, stop_failed", _SHAPES)
def test_the_cdk_nag_worker_reason(tmp_path, monkeypatch, extra, stop_failed):
    templates = _templates(tmp_path, 2)
    answers = {t.as_posix(): NOT_CFN for t in templates}
    inner = _fake_child(answers, [], returncode=124, answer_first=1, timed_out=True)

    def fake(command, **kwargs):
        outcome = inner(command, **kwargs)
        outcome.update(extra)
        return outcome

    _patch_spawn(monkeypatch, fake)
    outdir = tmp_path / "out"
    with cdk_nag_worker.cdk_nag_worker_batch(
        [str(t) for t in templates], outdir, timeout=5, values=()
    ):
        assert _call(templates[0], outdir) is None
        with pytest.raises(RuntimeError) as raised:
            _call(templates[1], outdir)

    _picks(str(raised.value), stop_failed)


def test_the_pair_is_the_operator_text():
    # Both literals are typed here on purpose: the cells above compare the pair
    # only with itself, so a reworded constant would pass them all.
    assert subprocess_utils.COULD_NOT_STOP_ENDING == (
        ", and ASH could not stop the tool, which may still be running"
    )
    assert subprocess_utils.WAS_KILLED_ENDING == " and was killed"


def test_the_ending_is_built_from_the_reason():
    assert subprocess_utils.COULD_NOT_STOP_ENDING == (
        ", and " + subprocess_utils.COULD_NOT_STOP_REASON
    )


def test_the_plugin_fallback_reason_tracks_the_pair(checkov):
    scanner, _ = checkov

    scanner._could_not_stop_state({"timed_out": True, "returncode": None})

    assert scanner.scan_could_not_stop is not None
    assert ", and " + scanner.scan_could_not_stop == (
        subprocess_utils.COULD_NOT_STOP_ENDING
    )


class _SalvagedCouldNotStopNoPidUnreadableText:
    """A could-not-stop timeout with no pid, whose stdout and error reads raise,
    so the uv mixin builds its own fallback reason."""

    args = ["uv", "tool", "run"]
    returncode = None
    stderr = ""
    timed_out = True
    could_not_stop = True

    def __getattr__(self, name: str):
        if name in ("stdout", "error"):
            raise RuntimeError(f"reading the run's {name} failed")
        raise AttributeError(name)


def test_the_uv_mixin_fallback_reason_tracks_the_pair(tmp_path, monkeypatch):
    scanner = _uv_scanner_whose_runner_returns(
        tmp_path, monkeypatch, _SalvagedCouldNotStopNoPidUnreadableText()
    )

    response = scanner._run_subprocess(
        command=["tool", "scan"], results_dir=tmp_path / "results"
    )

    reason = scanner.scan_could_not_stop or ""
    assert reason.startswith(subprocess_utils.COULD_NOT_STOP_REASON), reason
    assert str(response.get("error", "")).startswith(
        subprocess_utils.COULD_NOT_STOP_REASON
    ), response
