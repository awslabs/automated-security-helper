"""``--python-only`` decides which scanners run before ASH asks for their tools.

A scanner that is not Python-only is not part of a ``--python-only`` run, so whether
its tool is installed is not a fact about that run. The filter applies before the
dependency check, so on a host without cfn_nag, grype, npm, opengrep or syft those
five are SKIPPED, not MISSING, and the completeness gate passes a scan that ran every
scanner it was asked to run.

The other direction is held too: a Python-only scanner whose tool is absent is
MISSING, so the early filter does not hide a scanner the run needed.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults


def _plugin(name: str, *, python_only: bool, dependencies_satisfied: bool):
    cls = MagicMock(name=name)
    cls.__name__ = name
    instance = MagicMock()
    instance.__class__ = cls
    instance.__class__.__name__ = name
    config = MagicMock()
    config.enabled = True
    config.name = name
    instance.config = config
    instance.is_python_only.return_value = python_only
    instance.unsupported_platform_reason.return_value = None
    instance.validate_plugin_dependencies.return_value = dependencies_satisfied
    instance.dependencies_satisfied = dependencies_satisfied
    cls.return_value = instance
    return cls


def _run(tmp_path, plugins, python_only: bool):
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
        result = phase._execute_phase(
            aggregated_results=aggregated, python_based_plugins_only=python_only
        )
        queued = executor.call_args.kwargs["scanner_tasks"]
    return result.scanner_results, [name for name, _, _ in queued]


def test_a_non_python_scanner_without_its_tool_is_skipped_not_missing(tmp_path):
    grype = _plugin("grype", python_only=False, dependencies_satisfied=False)

    rows, _ = _run(tmp_path, [grype], python_only=True)

    assert rows["grype"].status == ScannerStatus.SKIPPED, (
        "--python-only leaves grype out of the run, so its absent tool must not make "
        f"it MISSING: {rows['grype']!r}"
    )
    assert rows["grype"].excluded is True


def test_the_dependency_check_is_not_asked_of_a_scanner_the_filter_left_out(tmp_path):
    grype = _plugin("grype", python_only=False, dependencies_satisfied=False)

    _run(tmp_path, [grype], python_only=True)

    grype.return_value.validate_plugin_dependencies.assert_not_called()


def test_a_python_scanner_without_its_tool_is_missing(tmp_path):
    bandit = _plugin("bandit", python_only=True, dependencies_satisfied=False)

    rows, _ = _run(tmp_path, [bandit], python_only=True)

    assert rows["bandit"].status == ScannerStatus.MISSING, rows["bandit"]


def test_only_python_scanners_are_queued(tmp_path):
    plugins = [
        _plugin("bandit", python_only=True, dependencies_satisfied=True),
        _plugin("grype", python_only=False, dependencies_satisfied=True),
    ]

    rows, queued = _run(tmp_path, plugins, python_only=True)

    assert queued == ["bandit"]
    assert rows["grype"].status == ScannerStatus.SKIPPED


def test_without_the_flag_a_non_python_scanner_runs(tmp_path):
    """Control: the filter applies only when asked for."""
    grype = _plugin("grype", python_only=False, dependencies_satisfied=True)

    _, queued = _run(tmp_path, [grype], python_only=False)

    assert queued == ["grype"]
