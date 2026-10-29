# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--config-overrides fail_on_findings=...`` decides the exit code in every mode.

A local scan applies the overrides to the config it scans with, and its exit
code follows the overridden ``fail_on_findings``. The container mode wrapper
used to hand the host's own exit-code computation the value the config *file*
holds, so the same command could pass with ``--mode local`` and fail with
``--mode container``.

The cells run the production entry (``run_ash_scan``) end to end and compare
the exit code. Container mode runs with the runner replaced by a stand-in that
does what the container's entrypoint does: it runs the same CLI entry in local
mode with the arguments the host built for it, writes its results where the
host reads them, and returns the entry's own exit status. No container runtime
is reached.
"""

from __future__ import annotations

import os
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.inner_run_outcome import OUTER_RUN_ID_ENV
from automated_security_helper.utils.subprocess_utils import create_completed_process
from tests.utils.helpers import stand_in_host_ids

AshConfig.model_rebuild()

_ENGINE = (
    "automated_security_helper.core.execution_engine.ScanExecutionEngine.execute_phases"
)
_METRICS = (
    "automated_security_helper.interactions.run_ash_scan.get_unified_scanner_metrics"
)


def _one_actionable_finding():
    metric = MagicMock()
    metric.actionable = 1
    metric.status = "FAILED"
    return [metric]


def _tree(tmp_path, file_value: bool):
    src = tmp_path / "src"
    src.mkdir(parents=True)
    (src / "app.py").write_text("x = 1\n", encoding="utf-8")
    # Inside the source directory: container mode refuses a --config outside it.
    config = src / ".ash.yaml"
    config.write_text(
        f"project_name: t\nfail_on_findings: {str(file_value).lower()}\n",
        encoding="utf-8",
    )
    return src, config


def _exit_code_of(mode: RunMode, tmp_path, monkeypatch, file_value, overrides, flag):
    """The exit code of one end to end scan that finds something."""
    src, config = _tree(tmp_path, file_value)
    out = tmp_path / "out"
    stand_in_host_ids(monkeypatch)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    inner_calls = []

    def container_stand_in(**kwargs):
        inner_calls.append(kwargs)
        # The entrypoint is this same CLI: it gets the host's arguments, and the
        # outer run's ID in its environment (the runner is handed it with -e), so
        # the inner run records that it completed and the host reads it back.
        code: Optional[int] = 0
        try:
            with patch.dict(os.environ, {OUTER_RUN_ID_ENV: kwargs["outer_run_id"]}):
                ras.run_ash_scan(
                    source_dir=str(src),
                    output_dir=str(out),
                    mode=RunMode.local,
                    config=str(config),
                    config_overrides=kwargs["config_overrides"],
                    fail_on_findings=kwargs["fail_on_findings"],
                    progress=False,
                    show_summary=False,
                    quiet=True,
                    min_severity="none",
                )
        except SystemExit as exited:
            code = exited.code
        return create_completed_process(args=[], returncode=code, stdout="", stderr="")

    def run(mode_):
        return ras.run_ash_scan(
            source_dir=str(src),
            output_dir=str(out),
            mode=mode_,
            config=str(config),
            config_overrides=overrides,
            fail_on_findings=flag,
            progress=False,
            show_summary=False,
            quiet=True,
            # The stand-in results carry no SARIF results, so a severity floor
            # would filter the one counted finding out.
            min_severity="none",
        )

    real_compute = ras._compute_exit_code
    trace = []

    def spy(results, opts, config_fof=None, *args, **kwargs):
        code = real_compute(results, opts, config_fof, *args, **kwargs)
        trace.append((opts.mode.value, opts.fail_on_findings, config_fof, code))
        return code

    with (
        patch.object(ras, "_compute_exit_code", spy),
        patch(_ENGINE, return_value=AshAggregatedResults()),
        patch(_METRICS, return_value=_one_actionable_finding()),
        patch.object(ras, "run_ash_container", side_effect=container_stand_in),
    ):
        try:
            run(mode)
            code = 0
        except SystemExit as exited:
            code = exited.code
    return code, trace


@pytest.mark.parametrize(
    "file_value, overrides, flag, expected",
    [
        (True, ["fail_on_findings=false"], None, 0),
        (False, ["fail_on_findings=true"], None, 2),
        (True, [], None, 2),
        (False, [], None, 0),
        (True, ["fail_on_findings=false"], True, 2),
        (False, ["fail_on_findings=true"], False, 0),
    ],
    ids=[
        "override-off-file-on",
        "override-on-file-off",
        "file-on-control",
        "file-off-control",
        "flag-on-beats-override-off",
        "flag-off-beats-override-on",
    ],
)
def test_container_and_local_mode_exit_with_the_same_code(
    tmp_path, monkeypatch, file_value, overrides, flag, expected
):
    local, local_trace = _exit_code_of(
        RunMode.local, tmp_path / "local", monkeypatch, file_value, overrides, flag
    )
    container, container_trace = _exit_code_of(
        RunMode.container,
        tmp_path / "container",
        monkeypatch,
        file_value,
        overrides,
        flag,
    )

    assert (local, container) == (expected, expected), (
        f"local exited {local}, container exited {container}, "
        f"expected {expected} for file={file_value} overrides={overrides} flag={flag}; "
        f"(mode, opts.fail_on_findings, config_fail_on_findings, code) calls: "
        f"local {local_trace}, container {container_trace}"
    )
