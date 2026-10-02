# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner whose constructor raises must not shrink the denominator.

Why this is a separate mechanism from ``test_scan_phase_unclassified_scanners``
------------------------------------------------------------------------------
That module covers a scanner that became an instance and then raised during
*filtering*. This one covers a scanner that never became an instance at all,
which takes a different route out of the phase and was left unrecorded by the
reconciliation that closed the first.

``ScanPhase`` builds every scanner inside ``try/except Exception``, logs one line,
and does not append to ``scanner_instances``. The later reconciliation loop walks
``scanner_instances``, so a class that failed to construct is not in the set being
reconciled -- deliberately, because an instance's ``config.name`` is the only
authoritative name a scanner has. The consequence was that the scanner appeared
nowhere: not in ``scanner_results``, not in ``summary_stats`` (whose five counters
still summed correctly over the scanners that remained), and therefore in neither
completeness gate. Expected and completed were both derived from the set that
survived, so the comparison could not detect a scanner that never joined it.

The measured trigger is the grep-family offline-cache verdict, which used to raise
from ``_process_config_options`` -- called from ``model_post_init``, so inside the
constructor. That verdict has moved, but the escape it travelled through is not
specific to it: any constructor that raises takes the same route, including a
third-party scanner's.

Recorded ERROR, not MISSING, and the two are not interchangeable even though both
fail the gate. MISSING carries the remediation "install the tool", which is a
misdirection for a constructor that raised -- nothing here established that any
tool is absent. ERROR says the scanner was reached and did not produce a result,
and the recorded error text names the exception. This differs from the
filtering-escape case above, which is MISSING precisely because it is reached
before any dependency question is asked.
"""

from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.interactions.run_ash_scan import (
    _COMPLETE_SCANNER_STATUSES,
    incomplete_scanners,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
)

BOOM = "offline rule cache absent, refused during _process_config_options"


def _unconstructable_scanner(name="explodes-in-init"):
    """A plugin class whose constructor raises.

    A plain class rather than a MagicMock: a Mock is constructible by definition,
    so it cannot express the case under test.
    """

    class _Explodes:
        def __init__(self, config=None, context=None):
            raise RuntimeError(BOOM)

    _Explodes.__name__ = name
    return _Explodes


def _healthy_scanner(name="bandit"):
    """A plugin that passes every filter and is queued for execution."""

    class _Healthy:
        def __init__(self, config=None, context=None):
            self.config = MagicMock()
            self.config.name = name
            self.config.enabled = True
            self.dependencies_satisfied = True

        def is_python_only(self):
            return True

        def unsupported_platform_reason(self):
            return None

        def validate_plugin_dependencies(self):
            return True

    _Healthy.__name__ = name
    return _Healthy


def _run_phase(tmp_path, plugin_classes):
    """Run ScanPhase over *plugin_classes* against a real validation manager.

    The executor is a double because every case here is decided during
    preparation, but it does write a PASSED entry for each scanner the phase
    queued: without that, a queued scanner is "queued but not completed", which
    ``ensure_complete_results`` correctly records as ERROR, and the healthy-scanner
    control would fail on the fixture rather than on the code under test.
    """
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
        plugins=list(plugin_classes),
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )

    double = MagicMock()
    double.completed_scanners = []

    def _run(model):
        for scanner_name, _instance, _tasks in phase._scanner_tasks:
            model.scanner_results[scanner_name] = ScannerStatusInfo(
                status=ScannerStatus.PASSED,
                excluded=False,
                dependencies_satisfied=True,
            )
            double.completed_scanners.append(scanner_name)
            phase.validation_manager.update_scanner_state(
                scanner_name, execution_completed=True
            )
        return model

    double.run_parallel.side_effect = _run
    double.run_sequential.side_effect = _run
    with patch(
        "automated_security_helper.core.phases.scan_phase.ScannerExecutor"
    ) as executor:
        executor.return_value = double
        return phase._execute_phase(aggregated_results=aggregated)


def test_a_scanner_that_could_not_be_constructed_is_recorded(tmp_path):
    """The defect. Before the fix this scanner had no entry at all."""
    results = _run_phase(tmp_path, [_unconstructable_scanner()])

    assert "explodes-in-init" in results.scanner_results, (
        "a scanner whose constructor raised vanished from the run: expected and "
        "completed both derive from the set that survived construction, so nothing "
        f"could detect it: {results.scanner_results}"
    )
    entry = results.scanner_results["explodes-in-init"]
    assert entry.status == ScannerStatus.ERROR, entry
    assert entry.excluded is False, (
        "excluded=True would launder a construction failure into a deliberate "
        "deselection, and SKIPPED is on the completeness allowlist"
    )


def test_the_completeness_gate_can_see_it(tmp_path):
    """The consequence, read through the function the exit code consults."""
    results = _run_phase(tmp_path, [_unconstructable_scanner()])

    assert incomplete_scanners(results) == [("explodes-in-init", "ERROR")], (
        "ERROR has to be outside "
        f"{sorted(_COMPLETE_SCANNER_STATUSES)} for this to reach the exit code"
    )


def test_the_recorded_error_names_the_cause(tmp_path):
    """The operator needs the exception text, not just a status.

    A bare ERROR for a scanner that never started is indistinguishable from one
    that ran and crashed mid-scan, and the remediation differs.
    """
    results = _run_phase(tmp_path, [_unconstructable_scanner()])

    rendered = str(results.additional_reports) + str(
        results.metadata.model_dump(mode="json")
    )
    assert BOOM in rendered, (
        "the constructor's own message has to survive into the results, or the "
        "only record of why the scanner did not run is a log line"
    )


def test_a_failure_beside_healthy_scanners_still_fails(tmp_path):
    """One scanner lost out of several leaves the rest to read clean on findings.

    "Did anything run" answers yes, so only the per-scanner status can report this
    one. This is the shape the set-level check cannot catch.
    """
    results = _run_phase(
        tmp_path, [_healthy_scanner("bandit"), _unconstructable_scanner()]
    )

    assert incomplete_scanners(results) == [("explodes-in-init", "ERROR")]
    assert results.scanner_results["bandit"].status == ScannerStatus.PASSED


def test_a_constructable_scanner_is_untouched(tmp_path):
    """The control. Recording construction failures must not perturb healthy ones."""
    results = _run_phase(tmp_path, [_healthy_scanner("bandit")])

    assert results.scanner_results["bandit"].status == ScannerStatus.PASSED
    assert incomplete_scanners(results) == []


def test_the_exit_code_is_non_zero_end_to_end(tmp_path):
    """The verdict, driven from a real scan phase rather than from mocked metrics.

    Every other assertion in this module reads the model. This one runs the phase
    and hands its output to the function that decides what ``ash scan`` returns, so
    the chain from "constructor raised" to "non-zero exit" is observed rather than
    inferred. The flag is passed explicitly because it defaults to False -- see the
    field description on ``AshConfig.fail_on_incomplete_scanners``; with it off this
    run exits 0 and the CI gate script is what holds the line.
    """
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _compute_exit_code,
    )

    results = _run_phase(
        tmp_path, [_healthy_scanner("bandit"), _unconstructable_scanner()]
    )
    opts = ScanOptions(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        fail_on_incomplete_scanners=True,
    )

    assert _compute_exit_code(results, opts) == 1, (
        "one scanner of two failed to construct and nine-tenths of a scan reads "
        "clean on findings alone; before the row existed this returned 0"
    )

    # The control, and it is the half that makes the assertion above mean anything.
    # _compute_exit_code returns 1 for several reasons -- findings, a null results
    # model, unevaluated rules -- so a 1 on its own does not show that the
    # construction failure caused it. The same harness with only the healthy scanner
    # has to return 0.
    healthy_only = _run_phase(tmp_path / "control", [_healthy_scanner("bandit")])
    control_opts = ScanOptions(
        source_dir=tmp_path / "control" / "src",
        output_dir=tmp_path / "control" / "out",
        fail_on_incomplete_scanners=True,
    )
    assert _compute_exit_code(healthy_only, control_opts) == 0, (
        "the fixture itself must not be what produces the non-zero exit"
    )


@pytest.mark.parametrize("config_name", ["cdk-nag", None])
def test_the_row_uses_the_configured_name_when_one_resolved(tmp_path, config_name):
    """The name has to be the one the rest of the run agrees on.

    ``config.name`` on an instance is the only authoritative name a scanner has,
    and a scanner that failed to construct has no instance. But the config is
    resolved BEFORE the constructor is called, so in the case that actually occurs
    -- a constructor that raises after its config resolved -- the authoritative
    name is available and must be used. Inventing a class-derived name there would
    put a scanner in the results under a name nothing else in the run matches:
    ``--exclude-scanners``, the shard partition and the report all key on
    ``config.name``.

    The ``None`` parametrization covers the narrower case where config resolution
    itself failed, where the class name is all there is.
    """
    cls = _unconstructable_scanner("cdknagscanner")

    context_config = get_default_config()
    if config_name is None:
        patched = patch.object(
            type(context_config),
            "get_plugin_config",
            side_effect=RuntimeError("config resolution failed"),
        )
    else:
        stub = MagicMock()
        stub.name = config_name
        patched = patch.object(
            type(context_config), "get_plugin_config", return_value=stub
        )

    for sub in ("src", "out", "work"):
        (tmp_path / sub).mkdir(parents=True, exist_ok=True)
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=context_config,
    )
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[cls],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    double = MagicMock()
    double.completed_scanners = []
    double.run_parallel.side_effect = lambda model: model
    double.run_sequential.side_effect = lambda model: model

    with patched:
        with patch(
            "automated_security_helper.core.phases.scan_phase.ScannerExecutor"
        ) as executor:
            executor.return_value = double
            results = phase._execute_phase(aggregated_results=aggregated)

    expected = config_name if config_name is not None else "cdknagscanner"
    assert expected in results.scanner_results, results.scanner_results
    assert results.scanner_results[expected].status == ScannerStatus.ERROR
