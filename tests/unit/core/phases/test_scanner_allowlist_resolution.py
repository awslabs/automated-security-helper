# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An allowlist that matched no registered scanner must refuse the scan.

The defect these pin
--------------------
``--scanners`` names are matched against ``config.name`` by exact string equality
after ``lower().strip()``, and nothing validated that a name given on the command
line corresponds to a scanner that exists. So a typo selected nothing, every
scanner took the not-selected path, and the run recorded ten SKIPPED entries.

Measured on this tree before the fix, against a one-file fixture::

    ash scan --scanners detect_secrets      # underscore; the name is detect-secrets
    -> scanner_results: Counter({'SKIPPED': 10})
    -> summary_stats:   passed=0 failed=0 missing=0 skipped=10 error=0
    -> exit code:       0

Zero findings from zero scanners is indistinguishable from a clean scan if you only
look at the findings, and SKIPPED cannot be the thing that gives it away: SKIPPED is
how sharding and ``--exclude-scanners`` express work a run was never meant to do, so
the completeness gate has to ignore it. That is what makes an unresolvable allowlist
a defect of its own rather than something an existing gate would have caught.

Why the check is here and not in the CLI
----------------------------------------
A scanner's selectable name is ``config.name`` on an *instantiated* plugin. Scanner
classes carry no class-level name and cannot be constructed without a plugin
context, so the CLI, the orchestrator and the execution engine can only guess -- the
same reason the shard partition is computed in this phase rather than earlier. This
is the first point at which the names are authoritative, and it is still before any
scanner runs, so the operator gets a refusal instead of a report about nothing.

Why a partial miss warns instead of raising
-------------------------------------------
``--scanners bandit,cdknag`` still scans bandit and still reports it, so it is not
the silent-zero case. It is also a shape a CI matrix can produce legitimately, when
runners load different ``--ash-plugin-modules``. The unresolved name is named in the
log either way; only "nothing at all resolved" is refused.
"""

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

# Imported for its side effect as well as for the name: importing this module is
# what calls ``AshAggregatedResults.model_rebuild()``, and without it constructing
# one raises PydanticUserError. Spelled out rather than left to whichever sibling
# test module happens to be collected first, so this file passes on its own.
from automated_security_helper.config.ash_config import AshConfig  # noqa: F401
from automated_security_helper.core.exceptions import ScannerSelectionError
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scanner_validation import ScannerValidationManager


#: Named with a hyphen because the real registered names use hyphens and the typo
#: this file exists for is an underscore. A fixture whose names had no punctuation
#: could not tell the two apart.
REGISTERED = ["detect-secrets", "bandit", "cfn-nag"]


@pytest.fixture
def mock_plugin_context(tmp_path):
    ctx = MagicMock()
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("print('hello')")
    (tmp_path / "work").mkdir()
    (tmp_path / "output").mkdir()
    ctx.source_dir = source_dir
    ctx.work_dir = tmp_path / "work"
    ctx.output_dir = tmp_path / "output"
    ctx.config = MagicMock()
    ctx.config.get_plugin_config.return_value = None
    ctx.config.global_settings.ignore_paths = []
    ctx.ignore_suppressions = False
    ctx.cached_source_files = []
    return ctx


def _make_scanner_class(name, enabled=True):
    """Callable scanner-class double whose class name differs from its config name.

    The gap is deliberate: ``DetectSecretsScanner`` carries
    ``config.name == "detect-secrets"``, so a double that set both to the same
    string could not tell whether the resolution read the config name or the class
    name.
    """
    class_name = name.replace("-", "").replace("_", "").capitalize() + "Scanner"
    plugin_cls = MagicMock()
    plugin_cls.__name__ = class_name

    instance = MagicMock()
    instance.__class__ = plugin_cls
    instance.__class__.__name__ = class_name

    config = MagicMock()
    config.name = name
    config.enabled = enabled
    config.options.severity_threshold = "HIGH"
    instance.config = config

    instance.validate_plugin_dependencies.return_value = True
    instance.dependencies_satisfied = True
    instance.is_python_only.return_value = True
    instance.errors = []
    instance.output = []
    instance.exit_code = 0
    instance.start_time = datetime(2024, 1, 1, 10, 0, 0)
    instance.end_time = datetime(2024, 1, 1, 10, 0, 5)
    instance.context = None

    plugin_cls.return_value = instance
    return plugin_cls


@pytest.fixture
def scan_phase(mock_plugin_context):
    """ScanPhase with a specced validation manager.

    ``spec=`` rather than a bare MagicMock, which would fabricate any attribute
    touched and so agree with a call to a method the real facade does not have.
    """
    with patch(
        "automated_security_helper.core.phases.scan_phase.ScannerValidationManager"
    ) as MockValMgr:
        val_mgr = MagicMock(spec=ScannerValidationManager)
        checkpoint = MagicMock()
        checkpoint.get_missing_scanners.return_value = []
        checkpoint.get_unexpected_scanners.return_value = []
        checkpoint.has_issues.return_value = False
        checkpoint.checkpoint_name = "test"
        checkpoint.timestamp = datetime(2024, 1, 1)
        checkpoint.expected_scanners = []
        checkpoint.actual_scanners = []
        checkpoint.discrepancies = []
        checkpoint.errors = []
        checkpoint.metadata = {}
        val_mgr.validate_task_queue.return_value = checkpoint
        val_mgr.validate_execution_completion.return_value = checkpoint
        val_mgr.ensure_complete_results.return_value = checkpoint
        val_mgr.report_execution_discrepancies.return_value = {}
        val_mgr.report_result_completeness.return_value = {}
        MockValMgr.return_value = val_mgr

        phase = ScanPhase(
            plugin_context=mock_plugin_context,
            plugins=[],
            progress_display=MagicMock(add_task=MagicMock(return_value=1)),
        )
        phase.validation_manager = val_mgr
        return phase


def _run(scan_phase, registered=REGISTERED, **kwargs):
    scan_phase.plugins = [_make_scanner_class(n) for n in registered]
    return scan_phase._execute_phase(
        aggregated_results=AshAggregatedResults(),
        parallel=False,
        **kwargs,
    )


def _scanned(result: AshAggregatedResults) -> set[str]:
    """Names that reached the scan path, read the way this phase records it.

    ``additional_reports[name]["source"]`` is written only for a scanner that was
    handed to the executor; a not-selected scanner gets the ``None`` key instead.
    Asserting on ``scanner_results`` would not distinguish them here -- the phase
    writes that map for the not-selected ones during preparation and leaves the
    executed ones to be filled in later, which these doubles do not reach.
    """
    return {
        name
        for name, targets in result.additional_reports.items()
        if isinstance(targets, dict) and "source" in targets
    }


def _not_selected(result: AshAggregatedResults) -> set[str]:
    return {
        name
        for name, status in result.scanner_results.items()
        if getattr(status, "excluded", False)
    }


class TestUnresolvableAllowlistIsRefused:
    def test_a_misspelled_scanner_name_refuses_the_scan(self, scan_phase):
        """The measured regression: underscore for hyphen used to exit 0."""
        with pytest.raises(ScannerSelectionError) as excinfo:
            _run(scan_phase, enabled_scanners=["detect_secrets"])

        message = str(excinfo.value)
        assert "detect_secrets" in message, (
            "the failure has to name the name that did not resolve, or it sends the "
            f"operator looking for a different problem: {message!r}"
        )
        assert "detect-secrets" in message, (
            "and it has to list the names that would have worked, which is the whole "
            f"difference between this and a bare non-zero exit: {message!r}"
        )

    @pytest.mark.parametrize("requested", ["cdknag", "Bandit3", "grype"])
    def test_every_shape_of_unresolvable_name_is_refused(self, scan_phase, requested):
        """A renamed scanner, a versioned guess, and one that is simply not here.

        ``grype`` is a real ASH scanner but is not registered in this fixture, which
        is the CI-relevant shape: a scanner removed from a build, or a plugin module
        that failed to load, leaves the operator's allowlist pointing at nothing.
        """
        with pytest.raises(ScannerSelectionError):
            _run(scan_phase, enabled_scanners=[requested])

    def test_nothing_is_recorded_as_having_been_scanned(self, scan_phase):
        """Refused before any scanner is touched, so there is no partial record.

        A results file carrying ten SKIPPED entries is the artifact that read as a
        clean scan. Raising before the per-scanner loop means no such file can be
        written for this run at all.
        """
        results = AshAggregatedResults()
        scan_phase.plugins = [_make_scanner_class(n) for n in REGISTERED]
        with pytest.raises(ScannerSelectionError):
            scan_phase._execute_phase(
                aggregated_results=results,
                parallel=False,
                enabled_scanners=["detect_secrets"],
            )

        assert results.scanner_results == {}, (
            "no scanner may be recorded when the allowlist resolved to nothing; a "
            "SKIPPED entry here is exactly the evidence the gate would read as clean"
        )

    def test_the_check_survives_a_shard_selection(self, scan_phase):
        """Sharding must not be a way around it.

        The partition is computed after this check, so a sharded run with a typo is
        refused rather than becoming a shard that owns nothing.
        """
        with pytest.raises(ScannerSelectionError):
            _run(
                scan_phase,
                enabled_scanners=["detect_secrets"],
                shard_index=0,
                shard_count=2,
            )

    def test_case_and_surrounding_space_still_resolve(self, scan_phase):
        """Control on the normalisation, not on the refusal.

        Selection matching is case-insensitive and strips whitespace, so the new
        check has to use the same rule. If it were stricter, ``--scanners BANDIT``
        would start being refused for a run that has always worked.
        """
        result = _run(scan_phase, enabled_scanners=["  BANDIT  "])
        assert _scanned(result) == {"bandit"}


class TestResolvableAllowlistsAreUntouched:
    """Controls. Without these, a check that refused everything would pass above."""

    def test_a_correct_allowlist_runs(self, scan_phase):
        result = _run(scan_phase, enabled_scanners=["detect-secrets"])
        assert _scanned(result) == {"detect-secrets"}
        assert _not_selected(result) == {"bandit", "cfn-nag"}

    def test_an_empty_allowlist_means_every_scanner_and_is_not_refused(
        self, scan_phase
    ):
        result = _run(scan_phase, enabled_scanners=[])
        assert _scanned(result) == set(REGISTERED)

    def test_no_allowlist_at_all_is_not_refused(self, scan_phase):
        result = _run(scan_phase)
        assert _scanned(result) == set(REGISTERED)

    def test_a_partly_unresolvable_allowlist_still_scans_what_resolved(
        self, scan_phase, caplog
    ):
        """Warns and continues, and the warning names the miss.

        Asserting on the log rather than only on the absence of an exception,
        because "did not raise" is also what a check that had been deleted would
        produce.
        """
        import logging

        with caplog.at_level(logging.WARNING):
            result = _run(scan_phase, enabled_scanners=["bandit", "cdknag"])

        assert _scanned(result) == {"bandit"}
        assert "cdknag" in caplog.text, (
            "an unresolved name has to be named even when the run continues, or the "
            f"operator never learns the scanner they asked for was dropped: {caplog.text!r}"
        )
