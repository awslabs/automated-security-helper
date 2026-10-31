# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner that repeats an earlier scanner's name is judged by selection first.

Why these tests exist
---------------------
Two registered scanner classes with one configured name cannot both run: the row,
the results directory, the shard and the ``--scanners`` matching all key on the
name. ``ScanPhase`` records the later one ERROR and leaves it out. That check ran
before any selection test, so a duplicate the operator had excluded, left out of
``--scanners``, or disabled in the configuration was recorded ERROR with
``excluded=False``, and the completeness gate failed a run that ran everything it
selected. Every other scanner is judged by selection before it is diagnosed.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit


def _plugin(class_name: str, config_name: str, *, enabled: bool = True):
    cls = MagicMock(name=class_name)
    cls.__name__ = class_name
    instance = MagicMock()
    instance.__class__ = cls
    instance.__class__.__name__ = class_name
    config = MagicMock()
    config.enabled = enabled
    config.name = config_name
    instance.config = config
    instance.is_python_only.return_value = True
    instance.unsupported_platform_reason.return_value = None
    instance.validate_plugin_dependencies.return_value = True
    instance.dependencies_satisfied = True
    cls.return_value = instance
    return cls


def _run(tmp_path, plugins, **phase_kwargs):
    for sub in ("src", "out", "work"):
        (tmp_path / sub).mkdir(parents=True, exist_ok=True)
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=plugins,
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    phase.validation_manager = MagicMock()
    with patch(
        "automated_security_helper.core.phases.scan_phase.ScannerExecutor"
    ) as executor:
        double = MagicMock()
        double.completed_scanners = []
        double.run_parallel.return_value = aggregated
        double.run_sequential.return_value = aggregated
        executor.return_value = double
        result = phase._execute_phase(aggregated_results=aggregated, **phase_kwargs)
        queued = executor.call_args.kwargs["scanner_tasks"]
    return result.scanner_results, [name for name, _, _ in queued]


def _errors(rows) -> list[str]:
    return [name for name, row in rows.items() if row.status == ScannerStatus.ERROR]


def test_an_excluded_name_shared_by_two_scanners_is_not_an_error(tmp_path):
    plugins = [_plugin("FirstDupe", "dupe"), _plugin("SecondDupe", "dupe")]

    rows, queued = _run(tmp_path, plugins, excluded_scanners=["dupe"])

    # Red at the base: the second scanner was recorded ERROR, excluded False.
    assert _errors(rows) == [], rows
    assert queued == []
    skipped = [r for r in rows.values() if r.status == ScannerStatus.SKIPPED]
    assert len(skipped) == 2
    assert all(row.excluded is True for row in skipped)


def test_a_name_left_out_of_the_allowlist_is_not_an_error(tmp_path):
    plugins = [
        _plugin("FirstDupe", "dupe"),
        _plugin("SecondDupe", "dupe"),
        _plugin("Other", "other"),
    ]

    rows, queued = _run(tmp_path, plugins, enabled_scanners=["other"])

    assert _errors(rows) == [], rows
    assert queued == ["other"]


def test_a_disabled_duplicate_is_skipped_and_the_first_still_runs(tmp_path):
    plugins = [
        _plugin("FirstDupe", "dupe"),
        _plugin("SecondDupe", "dupe", enabled=False),
    ]

    rows, queued = _run(tmp_path, plugins)

    assert _errors(rows) == [], rows
    assert queued == ["dupe"]


def test_two_selected_scanners_sharing_a_name_still_fail_the_second(tmp_path):
    """The control: a duplicate the run selected is still an error."""
    plugins = [_plugin("FirstDupe", "dupe"), _plugin("SecondDupe", "dupe")]

    rows, queued = _run(tmp_path, plugins)

    assert len(_errors(rows)) == 1, rows
    assert queued == ["dupe"]
