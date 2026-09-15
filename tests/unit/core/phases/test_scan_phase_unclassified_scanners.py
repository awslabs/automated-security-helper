# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner that raises during filtering must not be recorded as one nobody selected.

Why this file exists
--------------------
``ScanPhase``'s filtering loop ends in ``except Exception: continue``. A scanner whose
filtering raised therefore leaves that loop having written nothing: it is absent from
``enabled_scanner_names``, from ``excluded_scanner_names``, from
``dependency_error_scanners``, and from ``scanner_results``.

The ``getattr`` guard added alongside ``unsupported_platform_reason`` covers a plugin
that does not HAVE the hook. It does not cover one whose hook *raises*, which a
third-party scanner's can do for reasons of its own -- a config file it expects is
absent, a helper it shells out to fails. The escape is older and wider than that hook,
though: anything that raises before the recording lines takes the same route.

What that actually produced, and why it is not the absence it looks like
-----------------------------------------------------------------------
Measured, both ways, because the two harnesses disagree and only one of them is a scan.

* With the validation manager replaced by a ``MagicMock`` -- which is what
  ``test_scanner_platform_support._classify`` does -- the scanner has **no entry at
  all**.
* With the real ``ScannerValidationManager``, ``_validate_result_completeness`` calls
  ``ensure_complete_results``, which backfills an entry for every registered scanner
  missing from the results. ``validate_scanner_enablement`` has by then labelled the
  escaped scanner ``enablement_status="disabled"`` ("Scanner is disabled (reason
  unknown)"), ``determine_scanner_status_from_execution_data`` maps "disabled" to
  "excluded", and ``_create_missing_scanner_result_entry`` writes
  ``status=SKIPPED excluded=True dependencies_satisfied=True`` -- byte for byte what a
  scanner the operator deliberately deselected gets.

So the product behaviour was a mislabel, not an omission, and the mislabel is worse:
SKIPPED is on the completeness allowlist, so ``incomplete_scanners()`` returned ``[]``
and ``.github/scripts/assert_scanners_completed.py`` tolerated the entry. A scanner
that crashed was invisible to both gates, and the crash cost the run one scanner's
worth of coverage while every gate read clean.

Both harnesses are exercised here on purpose. A test written only against the mocked
manager would assert the absence -- which no scan ever sees -- and would keep passing
if the reconciliation only worked in that shape.
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

RAISED = "third-party hook blew up: expected config file not found"


def _raising_hook_scanner(name="raises-in-hook", dependencies_satisfied=True):
    """A plugin whose platform-decline hook raises.

    A plain class rather than a ``MagicMock``: a Mock returns a Mock from every method,
    so it cannot raise from one method and answer normally from the others, which is
    exactly the shape under test.
    """

    class _RaisingHook:
        def __init__(self, config=None, context=None):
            self.config = MagicMock()
            self.config.name = name
            self.config.enabled = True
            self.dependencies_satisfied = dependencies_satisfied

        def is_python_only(self):
            return True

        def unsupported_platform_reason(self):
            raise RuntimeError(RAISED)

        def validate_plugin_dependencies(self):
            return dependencies_satisfied

    _RaisingHook.__name__ = name
    return _RaisingHook


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


def _run_phase(
    tmp_path, plugin_classes, real_validation_manager: bool, at_dispatch=None
):
    """Run ScanPhase over *plugin_classes* and return the results model.

    The executor is a double, because every case here is decided during filtering. It
    does have to do the two things a real executor does for the scanners it was handed,
    though: write a PASSED entry for each and report it in ``completed_scanners``. A
    double that returned the model untouched leaves every queued scanner "queued but not
    completed", which ``ensure_complete_results`` correctly records as ERROR -- so the
    healthy-scanner controls below would fail on the fixture rather than on the code
    under test. Measured: they did.

    *real_validation_manager* selects between the two harnesses described in the module
    docstring. *at_dispatch*, when a dict is passed, receives a copy of
    ``scanner_results`` as it stood the moment the executor was called -- which is
    after the reconciliation and before any scanner result exists. That snapshot is the
    only place a queued scanner wrongly recorded MISSING is visible, because the
    executor overwrites its entry immediately afterwards. Measured: without it, the
    control below passes against a reconciliation that recorded every queued scanner
    MISSING.
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
    if not real_validation_manager:
        phase.validation_manager = MagicMock()

    double = MagicMock()
    double.completed_scanners = []

    def _run(model):
        if at_dispatch is not None:
            at_dispatch.update(dict(model.scanner_results))
        # phase._scanner_tasks is what filtering queued, so this stands in for
        # execution over exactly the set the phase decided to dispatch.
        for name, _instance, _tasks in phase._scanner_tasks:
            model.scanner_results[name] = ScannerStatusInfo(
                status=ScannerStatus.PASSED,
                excluded=False,
                dependencies_satisfied=True,
            )
            double.completed_scanners.append(name)
            if real_validation_manager:
                phase.validation_manager.update_scanner_state(
                    name, execution_completed=True
                )
        return model

    double.run_parallel.side_effect = _run
    double.run_sequential.side_effect = _run
    with patch(
        "automated_security_helper.core.phases.scan_phase.ScannerExecutor"
    ) as executor:
        executor.return_value = double
        return phase._execute_phase(aggregated_results=aggregated)


@pytest.mark.parametrize("real_validation_manager", [True, False])
def test_a_scanner_that_raised_during_filtering_is_recorded_missing(
    tmp_path, real_validation_manager
):
    """The defect, in both harnesses.

    Parametrized rather than written twice because the two shapes failed differently --
    absence under the mock, SKIPPED under the real manager -- and one fix has to answer
    both. Before the reconciliation this test failed on ``status == MISSING`` in one
    parametrization and on ``in results`` in the other.
    """
    results = _run_phase(
        tmp_path,
        [_raising_hook_scanner()],
        real_validation_manager=real_validation_manager,
    )

    assert "raises-in-hook" in results.scanner_results, (
        "a scanner that crashed during filtering vanished from the run entirely: "
        f"{results.scanner_results}"
    )
    entry = results.scanner_results["raises-in-hook"]
    assert entry.status == ScannerStatus.MISSING, (
        "SKIPPED says the operator deselected this scanner, which is what "
        "ensure_complete_results wrote and what made the crash invisible to the "
        f"completeness gate: {entry}"
    )
    assert entry.excluded is False, (
        "excluded=True is the field that launders a crash into a deliberate "
        "deselection, and it is what sends ensure_complete_results down its "
        "'properly excluded' branch"
    )
    assert entry.dependencies_satisfied is True, (
        "nothing here checked a dependency -- the platform hook is asked first -- so "
        "False would tell an operator to install a tool that may be present"
    )


@pytest.mark.parametrize("real_validation_manager", [True, False])
def test_the_completeness_gate_can_see_it(tmp_path, real_validation_manager):
    """The consequence, which is the point of the status choice.

    Asserted through ``incomplete_scanners`` rather than by re-reading the status,
    because that function is what the exit code and ``ash merge`` both consult, and it
    reads through ``get_unified_scanner_metrics`` rather than off ``scanner_results``
    directly. A status that were correct in the model but invisible through that path
    would fix nothing.
    """
    results = _run_phase(
        tmp_path,
        [_raising_hook_scanner()],
        real_validation_manager=real_validation_manager,
    )

    assert incomplete_scanners(results) == [("raises-in-hook", "MISSING")], (
        "before this fix the entry was SKIPPED, which is on "
        f"{sorted(_COMPLETE_SCANNER_STATUSES)}, so this list was empty and both the "
        "exit code and the CI gate reported a complete scan"
    )


def test_a_crashed_scanner_beside_healthy_ones_still_fails(tmp_path):
    """The shape that the set-level exit-code check cannot catch on its own.

    One scanner crashing out of ten leaves nine that ran, so "did anything run" answers
    yes and the run reads clean on findings alone. Only the per-scanner status can
    report this one, which is why the reconciliation has to produce a status the gate
    rejects rather than merely produce a status.
    """
    results = _run_phase(
        tmp_path,
        [_healthy_scanner("bandit"), _raising_hook_scanner("raises-in-hook")],
        real_validation_manager=True,
    )

    assert incomplete_scanners(results) == [("raises-in-hook", "MISSING")]


def test_a_queued_scanner_is_not_reconciled_as_missing(tmp_path):
    """The control. The reconciliation must not touch a scanner that filtering handled.

    A queued scanner has no ``scanner_results`` entry when the filtering loop ends --
    the executor writes it later -- so a reconciliation that checked only
    ``scanner_results``, and not the queued set beside it, records every healthy scanner
    in the run as MISSING.

    Asserted on the dispatch-time snapshot, not on the final model, and that distinction
    is the whole test. The executor overwrites the entry moments later, so a MISSING
    written by the reconciliation leaves no trace in the returned results: measured
    against that exact mutation, the final-model form of this test passed while two
    pre-existing suites in ``test_scanner_platform_support.py`` were the only things
    failing. A control that cannot see the mutation it names is not a control.
    """
    at_dispatch: dict = {}
    results = _run_phase(
        tmp_path,
        [_healthy_scanner("bandit")],
        real_validation_manager=True,
        at_dispatch=at_dispatch,
    )

    assert "bandit" not in at_dispatch, (
        "bandit passed every filter and was queued for execution, so the "
        "reconciliation must leave it alone; recording it MISSING would fail the "
        f"completeness gate on a healthy run: {at_dispatch}"
    )
    entry = results.scanner_results.get("bandit")
    assert entry is None or entry.status != ScannerStatus.MISSING, entry
    assert incomplete_scanners(results) == []


def test_a_deselected_scanner_is_still_skipped_not_missing(tmp_path):
    """The other control, on the status the fix has to leave alone.

    ``_record_scanner_not_selected`` is the path a config-disabled scanner takes, and it
    writes SKIPPED with ``excluded=True``. If the reconciliation ran over it too, every
    ``--scanners`` narrowing and every shard would report the scanners it did not own as
    MISSING and fail the gate.
    """
    disabled = _healthy_scanner("cdk-nag")
    original_init = disabled.__init__

    def _disabled_init(self, config=None, context=None):
        original_init(self, config=config, context=context)
        self.config.enabled = False

    disabled.__init__ = _disabled_init

    results = _run_phase(tmp_path, [disabled], real_validation_manager=True)

    entry = results.scanner_results["cdk-nag"]
    assert entry.status == ScannerStatus.SKIPPED
    assert entry.excluded is True
    assert incomplete_scanners(results) == []
