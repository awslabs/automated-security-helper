# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A local scan does not pre-read the config file for the exit-code gate.

The orchestrator's resolved config decides ``fail_on_findings`` in local mode
(``_run_local_mode`` answers it), and ``fail_on_incomplete_scanners`` is already
skipped there, so a full unchecked pre-read of the file was thrown away.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit


class _Stop(Exception):
    pass


class _QuietLogger:
    def __getattr__(self, name):
        return lambda *args, **kwargs: None


def _drive(tmp_path, monkeypatch, *, orchestrator_answer):
    calls = []
    gate = {}

    def loader(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("a local scan pre-read the config file")

    def compute(results, opts, config_fail_on_findings=None, *rest, **kwargs):
        gate["fail_on_findings"] = config_fail_on_findings
        raise _Stop

    source = tmp_path / "src"
    source.mkdir()
    (source / "a.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "out"
    output.mkdir()
    monkeypatch.setattr(ras, "_load_config_file_or_its_exit_fields", loader)
    monkeypatch.setattr(ras, "_setup_logger", lambda opts: _QuietLogger())
    monkeypatch.setattr(
        ras,
        "_run_local_mode",
        lambda opts, logger: (AshAggregatedResults(), orchestrator_answer),
    )
    monkeypatch.setattr(ras, "_gating_actionable_count", lambda *a, **k: 0)
    monkeypatch.setattr(ras, "_compute_exit_code", compute)
    with pytest.raises(_Stop):
        ras.run_ash_scan(
            source_dir=str(source),
            output_dir=str(output),
            mode=RunMode.local,
            show_summary=False,
        )
    return calls, gate


def test_local_mode_makes_no_config_pre_read(tmp_path, monkeypatch):
    calls, _ = _drive(tmp_path, monkeypatch, orchestrator_answer=False)

    assert calls == []


@pytest.mark.parametrize("answer", [True, False, None])
def test_the_gate_is_the_orchestrators_answer(tmp_path, monkeypatch, answer):
    _, gate = _drive(tmp_path, monkeypatch, orchestrator_answer=answer)

    assert gate["fail_on_findings"] is answer
