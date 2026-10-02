# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The completeness gate needs a denominator that is not the numerator.

The defect
----------
``expected_scanners`` derived from ``self._scanner_tasks``, which is built from
``plugin_modules('scanner')``, which is the resolved plugin set. Completed derived
from the same resolve. So a scanner that never joined the resolve -- because its
module failed to import, or because its constructor raised -- was absent from both
sides and produced no discrepancy. The five status counters summed correctly over
the scanners that remained, and ``_validate_result_completeness`` reported
"completeness rate: 100.0%" for a run that had lost scanners.

What the expected set is derived from instead
--------------------------------------------
``ScannerConfigSegment`` in ``config/ash_config.py``, which declares one typed
field per built-in scanner. That is a declaration fixed at class-definition time,
not a resolve -- and it is trustworthy in any run that has a config at all,
because ``ash_config`` imports each scanner's *config* class from the same module
as the scanner: if a scanner module were unimportable, config resolution would
have failed first and loudly.

Why it is recorded rather than compared in ``incomplete_scanners``
-----------------------------------------------------------------
Stated plainly because it is a real limit. ``incomplete_scanners`` feeds the exit
code, and making it fail on "config declares bandit, no row for bandit" would fire
on every caller that hands ``ScanPhase`` a narrow plugin set -- which is what ten
test harnesses in this suite do, and what a library caller constructing the phase
directly may legitimately do. So the roster is recorded in the results file, where
``.github/scripts/assert_scanners_completed.py`` turns it into a hard CI failure,
and the exit code gains the arms that cannot produce a false positive: a recorded
plugin-module import failure, and the empty-set split below.

The gating predicate is ``__module__``: a run whose plugin set contains a class
from the shipped built-in package resolved that package, so the built-in roster
applies to it. A run handed plugin doubles did not, and the roster does not.
"""

from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import (
    _BUILTIN_PLUGIN_MODULE_PREFIX,
    ScanPhase,
)
from automated_security_helper.interactions.run_ash_scan import (
    incomplete_scanners,
    no_scanner_ran,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
)


def _scanner_double(name, module=None):
    """A plugin that passes every filter, optionally posing as a built-in."""

    class _Double:
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

    _Double.__name__ = name
    if module is not None:
        _Double.__module__ = module
    return _Double


def _run_phase(tmp_path, plugin_classes, load_errors=None):
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
    # Patched on the loader rather than on scan_phase: the phase imports it inside
    # the function (a module-level import creates a pydantic forward-reference cycle
    # through config.ash_config), so the name is resolved from the loader at call
    # time and that is where the patch has to land.
    with patch(
        "automated_security_helper.plugins.loader.plugin_load_errors",
        return_value=dict(load_errors or {}),
    ):
        with patch(
            "automated_security_helper.core.phases.scan_phase.ScannerExecutor"
        ) as executor:
            executor.return_value = double
            return phase._execute_phase(aggregated_results=aggregated)


def test_the_builtin_module_prefix_matches_a_real_builtin_scanner():
    """The predicate's constant has to name where the shipped scanners live.

    A prefix that matched nothing would silently disable the roster on every real
    run while every test that spoofs ``__module__`` kept passing.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScanner,
    )

    assert BanditScanner.__module__.startswith(_BUILTIN_PLUGIN_MODULE_PREFIX)


def test_the_roster_is_recorded_for_a_run_that_resolved_the_builtin_set(tmp_path):
    """The declared roster reaches the results file, independent of the resolve."""
    results = _run_phase(
        tmp_path,
        [_scanner_double("bandit", module=f"{_BUILTIN_PLUGIN_MODULE_PREFIX}.scanners")],
    )

    expected = results.metadata.expected_scanners
    assert "bandit" in expected
    assert "detect-secrets" in expected, (
        "the roster comes from ScannerConfigSegment's declared fields, using the "
        f"alias the operator writes in config: {expected}"
    )
    assert "cdk-nag" in expected
    assert len(expected) >= 10, expected


def test_the_roster_names_a_scanner_that_never_joined_the_resolve(tmp_path):
    """The point of the whole exercise.

    One built-in scanner resolved; nine did not. Before this, expected and
    completed both came from the one that did, so there was no discrepancy to
    report.
    """
    results = _run_phase(
        tmp_path,
        [_scanner_double("bandit", module=f"{_BUILTIN_PLUGIN_MODULE_PREFIX}.scanners")],
    )

    unaccounted = [
        name
        for name in results.metadata.expected_scanners
        if name not in results.scanner_results
    ]
    assert "grype" in unaccounted, (
        "grype is declared in the config the run used and has no row, which is "
        f"exactly the state no gate could previously see: {unaccounted}"
    )


def test_an_injected_plugin_set_records_no_roster(tmp_path):
    """The control, and the reason the roster is gated rather than unconditional.

    A caller that hands ScanPhase its own plugin classes did not resolve the
    shipped built-in set, so the built-in roster says nothing about that run.
    Recording it anyway would report nine false MISSING scanners for every harness
    in this suite.
    """
    results = _run_phase(tmp_path, [_scanner_double("only-mine")])

    assert results.metadata.expected_scanners == []
    assert incomplete_scanners(results) == [], (
        "a run with its own plugin set must stay clean; this is the assertion that "
        "breaks if the roster is applied unconditionally"
    )


def test_a_failed_plugin_module_is_recorded_and_fails_the_gate(tmp_path):
    """Import loss has to reach the exit code, not only a log line.

    Per-module import isolation turns a hard startup failure into a degraded run,
    which is only the right direction if the degradation is loud. This is the arm
    that makes it loud, and nothing else in this phase carries that signal.

    The row is keyed by the module path, which is what required narrowing
    ``cli.merge._verify_scanner_union``: that check refuses any ``scanner_results``
    key no shard's ``assigned_scanners`` claims, and a module can never be claimed.
    The two changes are one decision.
    """
    failed = f"{_BUILTIN_PLUGIN_MODULE_PREFIX}.scanners"
    results = _run_phase(
        tmp_path,
        [_scanner_double("bandit", module=f"{_BUILTIN_PLUGIN_MODULE_PREFIX}.scanners")],
        load_errors={failed: "ImportError: No module named 'detect_secrets'"},
    )

    assert failed in results.metadata.plugin_load_errors
    assert failed in results.scanner_results, (
        "a scanner-region module that failed to import has to leave a row, or the "
        f"plugins it declares are lost with nothing to fail on: {results.scanner_results}"
    )
    assert results.scanner_results[failed].status == ScannerStatus.ERROR
    assert (failed, "ERROR") in incomplete_scanners(results)


def test_a_failed_reporter_module_is_recorded_but_is_not_a_scanner_row(tmp_path):
    """Scope control on the row.

    ``scanner_results`` is keyed by scanner name and rendered as a scanner column,
    so a failed reporter module does not belong in it -- it costs the run no
    scanners. It is still recorded, in the metadata field that exists for it, and the
    CI gate fails the job on that.
    """
    failed = f"{_BUILTIN_PLUGIN_MODULE_PREFIX}.reporters"
    results = _run_phase(
        tmp_path,
        [_scanner_double("bandit", module=f"{_BUILTIN_PLUGIN_MODULE_PREFIX}.scanners")],
        load_errors={failed: "ImportError: boom"},
    )

    assert failed in results.metadata.plugin_load_errors
    assert failed not in results.scanner_results


def test_a_lost_plugin_module_is_a_non_zero_exit_end_to_end(tmp_path):
    """The verdict, driven from a real scan phase rather than from mocked metrics.

    Per-module import isolation is only safe if the loss reaches the exit code, and
    this is the assertion that says it does. The flag is passed explicitly because it
    defaults to False, so on a default run the CI gate script is what holds the line.
    """
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _compute_exit_code,
    )

    results = _run_phase(
        tmp_path,
        [_scanner_double("bandit", module=f"{_BUILTIN_PLUGIN_MODULE_PREFIX}.scanners")],
        load_errors={
            f"{_BUILTIN_PLUGIN_MODULE_PREFIX}.scanners": (
                "ImportError: No module named 'detect_secrets'"
            )
        },
    )
    opts = ScanOptions(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        fail_on_incomplete_scanners=True,
    )

    assert _compute_exit_code(results, opts) == 1, (
        "bandit ran and found nothing, so findings alone read clean; only the "
        "recorded import failure can make this run report itself incomplete"
    )

    # The control. _compute_exit_code returns 1 for several reasons, so the same
    # harness with no recorded load error has to return 0 or the assertion above is
    # measuring the fixture.
    clean = _run_phase(
        tmp_path / "control",
        [_scanner_double("bandit", module=f"{_BUILTIN_PLUGIN_MODULE_PREFIX}.scanners")],
    )
    control_opts = ScanOptions(
        source_dir=tmp_path / "control" / "src",
        output_dir=tmp_path / "control" / "out",
        fail_on_incomplete_scanners=True,
    )
    assert _compute_exit_code(clean, control_opts) == 0, (
        "a run that lost no plugin module must exit 0, including one whose recorded "
        "roster names nine scanners it did not run -- the roster is CI's gate, not "
        "the exit code's, and this is where that boundary is held"
    )


class TestEmptySetSplit:
    """``no_scanner_ran``'s empty-set exemption, split into its two causes.

    The exemption was documented and correct as far as it went: an empty scanner
    set is reachable from a legitimate ``--phases convert`` run, and failing that
    would break a phase-limited scan. But it also covers "the scan phase ran and
    had nothing to run", which is not benign at all, and one boolean could not tell
    them apart.

    The roster is what tells them apart, and it does so without a new state:
    ``ScanPhase`` records it, so a recorded roster means the scan phase ran. No
    roster and no scanners means the phase was never requested.
    """

    def test_an_empty_set_with_no_roster_stays_benign(self):
        assert no_scanner_ran([], expected=[]) is False
        assert no_scanner_ran([]) is False, (
            "the default has to stay benign for callers that pass no roster, "
            "including a results file written by an ASH that recorded none"
        )

    def test_an_empty_set_with_a_roster_is_not_benign(self):
        assert no_scanner_ran([], expected=["bandit", "grype"]) is True

    @pytest.mark.parametrize("expected", [[], ["bandit"]])
    def test_a_set_that_ran_is_unaffected_either_way(self, expected):
        assert no_scanner_ran([("bandit", "PASSED")], expected=expected) is False

    @pytest.mark.parametrize("expected", [[], ["bandit"]])
    def test_an_all_skipped_set_still_fails_either_way(self, expected):
        assert no_scanner_ran([("bandit", "SKIPPED")], expected=expected) is True
