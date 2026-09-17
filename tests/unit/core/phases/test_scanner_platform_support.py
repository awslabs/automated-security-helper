# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner with no build for this platform is SKIPPED, not MISSING.

Why this file exists
--------------------
``validate_plugin_dependencies`` answers "can this scanner run here" with one boolean,
and two unrelated states were sharing that False: a tool that is not installed, and a
tool that has no build for this platform at all. ScanPhase classified both as MISSING,
which means "this scanner was supposed to run and did not" -- so it fails the
completeness gate and tells an operator to install something.

Measured on ``scan (python-local, windows-latest)``, run_attempt 1: semgrep logged
"Semgrep is not supported on Windows and will be skipped", was recorded MISSING, and its
installer status was INSTALLED with a real path at ``...\\uv-tool-bin-dir\\semgrep.EXE``.
So nothing was unprovisioned and no install would have helped. Every Windows leg would
have failed the completeness gate for a scanner that is permanently and deliberately
absent there -- a false failure from the gate, on the platform where it is least
defensible.

BOTH DIRECTIONS, AND WHY THAT IS THE POINT
------------------------------------------
The fix widens what the gate tolerates, which is the same shape as the bug it replaced:
the five in-line guards this branch removed were each broken in a way that made them
pass. So half of these tests assert the new tolerance (a declared platform decline
reaches SKIPPED and the gate accepts it) and half assert it did NOT widen any further:
an ordinary missing dependency is still MISSING and still fails, a scanner that declares
nothing is untouched, and a results file in which every scanner is SKIPPED still fails.

Without that second half, ``unsupported_platform_reason`` returning a truthy value
unconditionally would satisfy every test here while turning the gate into a no-op.
"""

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.interactions.run_ash_scan import (
    _COMPLETE_SCANNER_STATUSES,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    semgrep_scanner,
)

# tests/unit/core/phases/ -> four levels up is the repository root. Asserted rather than
# trusted: an off-by-one here does not fail at import, it fails once per gate test with a
# FileNotFoundError naming a path under tests/, which reads as a missing script rather
# than a wrong constant.
REPO_ROOT = Path(__file__).resolve().parents[4]
GATE_PATH = REPO_ROOT / ".github" / "scripts" / "assert_scanners_completed.py"
assert GATE_PATH.is_file(), f"gate script not found at {GATE_PATH}"


def _load_gate():
    """Import the completeness gate by path; ``.github/scripts`` is not a package."""
    spec = importlib.util.spec_from_file_location(
        "ash_platform_support_gate_probe", GATE_PATH
    )
    assert spec is not None and spec.loader is not None, GATE_PATH
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _run_gate(tmp_path, scanner_results):
    path = tmp_path / "ash_aggregated_results.json"
    path.write_text(json.dumps({"scanner_results": scanner_results}), encoding="utf-8")
    argv = sys.argv
    sys.argv = ["assert_scanners_completed.py", str(path)]
    try:
        return gate.main()
    finally:
        sys.argv = argv


def _entry(status):
    return {"status": status, "dependencies_satisfied": True, "excluded": False}


# ---------------------------------------------------------------------------
# The hook itself
# ---------------------------------------------------------------------------


def test_the_base_class_declares_nothing_unsupported():
    """The default has to be None, or every scanner inherits a decline.

    This is the control for the whole change. ``unsupported_platform_reason`` returning
    anything truthy from the base class would route every scanner in the app to SKIPPED
    and make the completeness gate vacuous -- the exact failure mode the gate exists to
    end. Asserted on the unbound function so no instance construction is needed.
    """
    assert ScannerPluginBase.unsupported_platform_reason(object()) is None


@pytest.mark.parametrize("system", ["Windows", "windows", "WINDOWS"])
def test_semgrep_declares_windows_unsupported(system, monkeypatch):
    monkeypatch.setattr(semgrep_scanner.platform, "system", lambda: system)
    reason = semgrep_scanner.SemgrepScanner.unsupported_platform_reason(object())
    assert isinstance(reason, str) and reason, reason
    assert "Windows" in reason


@pytest.mark.parametrize("system", ["Linux", "Darwin"])
def test_semgrep_declares_nothing_on_platforms_it_supports(system, monkeypatch):
    """The other direction, and it is not symmetric with the test above.

    A reason returned everywhere would make semgrep SKIPPED on Linux too -- which is
    where it actually finds things, so the scan would go green having measured nothing.
    That is worse than the bug being fixed.
    """
    monkeypatch.setattr(semgrep_scanner.platform, "system", lambda: system)
    assert semgrep_scanner.SemgrepScanner.unsupported_platform_reason(object()) is None


# ---------------------------------------------------------------------------
# The classification in ScanPhase
# ---------------------------------------------------------------------------


def _plugin(name, unsupported_reason, dependencies_satisfied=True):
    """A scanner plugin class double whose two verdicts can be set independently.

    ``unsupported_reason`` is passed through exactly as given, including a non-str, so a
    test can drive the isinstance guard in ScanPhase rather than only the happy path.
    """
    cls = MagicMock(name=name)
    cls.__name__ = name
    instance = MagicMock()
    instance.__class__ = cls
    instance.__class__.__name__ = name
    config = MagicMock()
    config.enabled = True
    config.name = name
    instance.config = config
    instance.is_python_only.return_value = True
    instance.unsupported_platform_reason.return_value = unsupported_reason
    instance.validate_plugin_dependencies.return_value = dependencies_satisfied
    instance.dependencies_satisfied = dependencies_satisfied
    cls.return_value = instance
    return cls


def _classify(tmp_path, plugin_cls):
    """Run ScanPhase over one plugin and return its recorded ScannerStatusInfo.

    The executor is stubbed out because nothing here is about running a scanner: every
    case under test is decided before dispatch, which is the point -- ScanPhase decides
    MISSING versus SKIPPED without the scanner participating.
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
        plugins=[plugin_cls],
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
        result = phase._execute_phase(aggregated_results=aggregated)
    return result.scanner_results


def _semgrep_on_windows():
    """The real shape, not an approximation of it.

    ``dependencies_satisfied=False`` matters: semgrep's own
    ``validate_plugin_dependencies`` still returns False on Windows, because the answer to
    "can this run here" is still no. That False is what ScanPhase used to read as MISSING.
    A double that returned True would make the routing test pass for the wrong reason --
    remove the routing and the scanner is simply dispatched, so the test would prove "not
    SKIPPED" rather than reproducing the defect. Measured: with the routing disabled this
    double records MISSING, which is exactly what windows-latest reported.
    """
    return _plugin(
        "semgrep", "semgrep publishes no Windows build", dependencies_satisfied=False
    )


def test_a_declared_platform_decline_is_recorded_skipped(tmp_path):
    results = _classify(tmp_path, _semgrep_on_windows())
    assert "semgrep" in results, results
    assert results["semgrep"].status == ScannerStatus.SKIPPED, (
        "the declared decline must not land on MISSING, which is what failed every "
        f"Windows leg: {results['semgrep']}"
    )
    # SKIPPED alone is not the whole contract. ``_record_scanner_not_selected`` is the one
    # recording path for "not part of this run", and the gate reads the status while
    # reporters read these two fields; a SKIPPED entry still claiming unsatisfied
    # dependencies would say the tool is broken here, which is the claim being removed.
    assert results["semgrep"].excluded is True
    assert results["semgrep"].dependencies_satisfied is True


def test_a_declared_platform_decline_never_reaches_the_dependency_check(tmp_path):
    """Asked before ``validate_plugin_dependencies``, not after.

    Order is the fix. Asking afterwards means reading a boolean that has already lost the
    distinction, and it also makes the scanner probe for a tool that cannot exist on this
    platform -- for semgrep that is a UV tool install attempt reaching the network.
    """
    plugin_cls = _semgrep_on_windows()
    _classify(tmp_path, plugin_cls)
    plugin_cls.return_value.validate_plugin_dependencies.assert_not_called()


def test_an_ordinary_missing_dependency_is_still_recorded_missing(tmp_path):
    """The tolerance did not widen past the declared case.

    Same shape as the test above with one field changed: nothing declared, dependencies
    absent. If this went to SKIPPED too, the fix would have re-created the silent-clean
    bug the completeness gate exists to end.
    """
    results = _classify(tmp_path, _plugin("grype", None, dependencies_satisfied=False))
    assert "grype" in results, results
    assert results["grype"].status == ScannerStatus.MISSING


def test_a_scanner_declaring_nothing_runs_normally(tmp_path):
    results = _classify(tmp_path, _plugin("bandit", None))
    # Not SKIPPED and not MISSING: it was dispatched, so ScanPhase records nothing here
    # and the executor double owns the outcome.
    assert results.get("bandit") is None or results["bandit"].status not in (
        ScannerStatus.SKIPPED,
        ScannerStatus.MISSING,
    )


def test_a_plugin_without_the_hook_still_reaches_the_dependency_check(tmp_path):
    """A scanner that predates the hook must be unaffected, not silently dropped.

    Nothing requires a scanner plugin to inherit ``ScannerPluginBase``, so a plugin written
    before ``unsupported_platform_reason`` existed does not have it -- including every
    out-of-tree scanner on the upgrade that introduces this. Calling it unguarded raises
    AttributeError, and the filtering loop's own except-and-continue swallows that, so the
    scanner vanishes from the run without a status: no SKIPPED, no MISSING, nothing.

    MEASURED, not hypothesised. The first version of this change called the hook directly
    and broke exactly two suites in test_scan_phase_validation_paths.py, whose plugin
    doubles are plain classes -- and it broke them by going quiet, which is the failure
    class this whole branch exists to remove. Hence the ``getattr`` in ScanPhase, and hence
    this test: the plugin here has no hook at all and must still be classified MISSING on
    its dependency verdict.
    """

    class _NoHook:
        """A scanner-shaped plugin from before the hook, with dependencies absent."""

        def __init__(self, config=None, context=None):
            self.config = MagicMock()
            self.config.name = "legacy-scanner"
            self.config.enabled = True
            self.dependencies_satisfied = False

        def is_python_only(self):
            return True

        def validate_plugin_dependencies(self):
            return False

    assert not hasattr(_NoHook, "unsupported_platform_reason"), (
        "fixture check: this plugin has to be missing the hook for the test to mean "
        "anything"
    )
    results = _classify(tmp_path, _NoHook)
    assert "legacy-scanner" in results, (
        "the scanner was dropped without a status, which is the silent failure the "
        f"getattr guard exists to prevent: {results}"
    )
    assert results["legacy-scanner"].status == ScannerStatus.MISSING


def test_a_non_string_reason_does_not_count_as_a_decline(tmp_path):
    """The isinstance guard in ScanPhase, and it protects the rest of the suite.

    A bare ``MagicMock`` returns a truthy Mock from any method it was not told about, and
    the plugin doubles in several existing scan-phase suites are exactly that. Without
    the guard every one of them would route to SKIPPED -- the completeness gate would
    read as "tolerate everything" while every test still passed.
    """
    results = _classify(tmp_path, _plugin("bandit", MagicMock()))
    assert results.get("bandit") is None or results["bandit"].status not in (
        ScannerStatus.SKIPPED,
        ScannerStatus.MISSING,
    )


@pytest.mark.parametrize("reason", ["", None])
def test_an_empty_reason_does_not_count_as_a_decline(tmp_path, reason):
    """An empty string is not a justification, so it must not buy tolerance.

    A scanner that returned "" would otherwise be SKIPPED with no reason recorded, which
    is the unexplained silence this whole gate exists to remove.
    """
    results = _classify(
        tmp_path, _plugin("grype", reason, dependencies_satisfied=False)
    )
    assert results["grype"].status == ScannerStatus.MISSING


# ---------------------------------------------------------------------------
# The consequence at the gate
# ---------------------------------------------------------------------------


def test_the_gate_tolerates_the_windows_shape_it_used_to_fail(tmp_path):
    """The end the fix exists for, in the shape measured on windows-latest.

    detect-secrets and npm-audit both ship with the image and pass there; semgrep is
    permanently absent. With semgrep MISSING this file exits 1 and the leg is red for a
    scanner that cannot exist; as SKIPPED it exits 0 while still having measured
    something.
    """
    assert (
        _run_gate(
            tmp_path,
            {
                "detect-secrets": _entry("PASSED"),
                "npm-audit": _entry("PASSED"),
                "semgrep": _entry("SKIPPED"),
            },
        )
        == 0
    )


def test_the_gate_still_fails_the_same_shape_with_semgrep_missing(tmp_path):
    """The control for the test above: it passes because of the status, not the names."""
    assert (
        _run_gate(
            tmp_path,
            {
                "detect-secrets": _entry("PASSED"),
                "npm-audit": _entry("PASSED"),
                "semgrep": _entry("MISSING"),
            },
        )
        == 1
    )


def test_the_gate_still_fails_an_undeclared_missing_scanner_beside_a_skipped_one(
    tmp_path,
):
    """cfn-nag on Windows is a provisioning gap, not a platform decline.

    It is being fixed elsewhere by supplying a Windows Ruby toolchain, so it must stay
    MISSING and must keep failing the gate -- a SKIPPED sibling does not launder it.
    """
    assert (
        _run_gate(
            tmp_path,
            {
                "detect-secrets": _entry("PASSED"),
                "semgrep": _entry("SKIPPED"),
                "cfn-nag": _entry("MISSING"),
            },
        )
        == 1
    )


def test_the_gate_still_fails_when_every_scanner_is_skipped(tmp_path):
    """The assertion the fix must not break.

    SKIPPED is tolerated one entry at a time, so widening what lands there makes the
    all-SKIPPED case more reachable, not less. A run that selected nothing has shown the
    target to be neither clean nor dirty.
    """
    assert (
        _run_gate(
            tmp_path,
            {"semgrep": _entry("SKIPPED"), "opengrep": _entry("SKIPPED")},
        )
        == 1
    )


def test_skipped_is_on_the_completeness_allowlist_and_missing_is_not():
    """Fixture check for every gate assertion above, against the package's own set.

    The gate script spells these as literals because it runs where ASH is not
    importable, so this is where the two are held together. If they ever diverge the
    tests above would still pass while the shipped gate disagreed with the shipped
    scan.
    """
    assert ScannerStatus.SKIPPED.value in _COMPLETE_SCANNER_STATUSES
    assert ScannerStatus.MISSING.value not in _COMPLETE_SCANNER_STATUSES
    assert set(gate.COMPLETE_STATUSES) == _COMPLETE_SCANNER_STATUSES


def test_the_gate_and_the_exit_code_agree_on_which_statuses_mean_ran():
    """The second set the two implementations share, held together the same way.

    ``test_the_gate_still_fails_when_every_scanner_is_skipped`` above drives
    ``gate.main()``, so it passed throughout the window in which ``ash scan`` answered 0
    on the same results file: the script asserted the set-level condition and
    ``_compute_exit_code`` had no counterpart. It now has one, and the two sets are
    spelled separately -- the script cannot import ASH, because the bash and PowerShell
    scan methods leave no ASH on the runner's PATH -- so this is the only thing holding
    them in step.

    ``ScannerStatus`` is checked as well, so a rename of PASSED or FAILED fails here
    rather than silently emptying one side of the comparison.
    """
    from automated_security_helper.interactions.run_ash_scan import (
        _RAN_SCANNER_STATUSES,
    )

    assert set(gate.RAN_STATUSES) == _RAN_SCANNER_STATUSES
    assert _RAN_SCANNER_STATUSES == {
        ScannerStatus.PASSED.value,
        ScannerStatus.FAILED.value,
    }
