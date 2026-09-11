# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``fail_on_incomplete_scanners``: the exit code has to be able to say "nothing was checked".

Why these tests exist
---------------------
``_compute_exit_code`` derived the verdict from finding counts alone. A run where
every selected scanner failed to start therefore exited 0 -- the same code as a
clean scan -- because zero scanners produced zero findings. Measured on this
tree: ``ash scan --scanners bandit`` against a one-file fixture reports
``cdk-nag``, ``cfn-nag``, ``grype`` and ``syft`` as MISSING and still exits 0, and
a deployed run with five of ten scanners MISSING or ERROR exited 0 on a
repository that a working scan flags at HIGH.

The distinction that makes the fix correct
------------------------------------------
``ScannerStatus`` has five members and only two of them mean "selected and did
not complete":

* ``ERROR``   -- ran and failed.
* ``MISSING`` -- was selected, its dependencies were unavailable, never ran.
* ``SKIPPED`` -- was not selected at all. **Must stay exit 0.** This is the
  mechanism sharding itself uses: ``core.sharding.exclusions_for_shard`` excludes
  every scanner another shard owns, and those land as SKIPPED in this shard's
  results. A check that treated SKIPPED as incomplete would fail every shard of
  every sharded scan, which is why ``test_skipped_scanners_never_trip_the_gate``
  is here and not merely implied.
* ``PASSED`` / ``FAILED`` -- ran to completion, verdict already carried by the
  finding count.

Independence from ``fail_on_findings`` is asserted directly. The two knobs answer
different questions -- "was anything found" versus "did what I asked for run" --
and ``_compute_exit_code`` returns early when ``fail_on_findings`` is false, so a
check placed after that early return would be silently disabled for every
operator who runs with findings-gating off. That is the one wiring mistake that
would leave the defect in place while every other test still passed.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core.enums import RunMode, ScannerStatus
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _compute_exit_code,
)

_MODULE = "automated_security_helper.interactions.run_ash_scan"


def _metric(scanner_name: str, status: str, actionable: int = 0):
    """One entry as ``get_unified_scanner_metrics`` would return it.

    A MagicMock rather than a real ``ScannerMetrics`` so a test can pin a status
    string that the calculator would never derive together with that finding
    count -- the point is to exercise the exit-code rule, not the calculator.
    """
    metric = MagicMock()
    metric.scanner_name = scanner_name
    metric.status = status
    metric.actionable = actionable
    return metric


def _opts(tmp_path, **kwargs) -> ScanOptions:
    return ScanOptions(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        **kwargs,
    )


class TestIncompleteScannersTripTheGate:
    """A selected scanner that did not complete must not read as a clean scan."""

    @pytest.mark.parametrize(
        "status", [ScannerStatus.MISSING.value, ScannerStatus.ERROR.value]
    )
    def test_incomplete_scanner_with_no_findings_exits_one(self, tmp_path, status):
        """Zero findings plus one incomplete scanner is exit 1, not exit 0.

        This is the defect in its smallest form: nothing was found because
        nothing ran.
        """
        opts = _opts(tmp_path, fail_on_incomplete_scanners=True)
        results = MagicMock()
        results.sarif = None

        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[_metric("cdk-nag", status)],
        ):
            code = _compute_exit_code(results, opts)

        assert code == 1, (
            f"a scanner in {status} means the scan is incomplete; exit 0 would be "
            f"indistinguishable from a clean run"
        )

    def test_the_default_fails_a_scan_with_an_incomplete_scanner(self, tmp_path):
        """The regression test. Nothing is passed, so this is the default's answer.

        This is the assertion that was inverted, and the inversion is the whole
        defect. The gate shipped opt-in, on the argument that turning it on by
        default would redden CI in every environment lacking a scanner's tool.
        That is true and it is not a reason: those runs were already not measuring
        what they claimed to measure, and a green check run is how nobody found
        out. Measured on the pull request that prompted this, on GREEN check runs:
        ``scan (python-local, windows-latest)`` had four of ten scanners MISSING
        (cfn-nag, grype, semgrep, syft), each at under a millisecond, and the three
        ubuntu/macos python-local cells had three each. In the cells where semgrep
        did run it reported 82 findings. The green Windows cell was not clean, it
        was unmeasured.

        Nothing is passed for ``fail_on_incomplete_scanners`` here, on the command
        line or in a config, so what this pins is precisely the value an operator
        who never heard of the flag gets. ``results`` is a MagicMock, whose
        ``ash_config`` attribute auto-creates to another MagicMock rather than a
        bool, so ``_resolve_fail_on_incomplete_scanners`` falls through its config
        steps to the final default -- which is the one this test is about.

        Discrimination check, run before this was committed: against the
        pre-change tree this test fails with ``assert 0 == 1``, because the default
        was off and both an ERROR and a MISSING scanner produced exit 0. Every
        other test in this file passes under either version, which is why this one
        is the regression test and they are not.
        """
        opts = _opts(tmp_path)
        results = MagicMock()
        results.sarif = None

        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[
                _metric("cdk-nag", ScannerStatus.MISSING.value),
                _metric("grype", ScannerStatus.ERROR.value),
            ],
        ):
            code = _compute_exit_code(results, opts)

        assert code == 1, (
            "with no flag and no config, a scan carrying a MISSING and an ERROR "
            "scanner must not exit 0 -- that code is indistinguishable from a scan "
            "where all ten ran and found nothing"
        )

    def test_the_default_comes_from_the_config_model_not_just_the_fallback(
        self, tmp_path
    ):
        """The same default, reached through a real AshConfig rather than a mock.

        Separate from the test above because the two exercise different steps of
        ``_resolve_fail_on_incomplete_scanners`` and only one of them is the path a
        real scan takes. A real run has a resolved config on ``results``, so it
        stops at the ``isinstance(..., bool)`` step and never reaches the final
        fallback; a hand-built results object reaches the fallback. Both had to be
        flipped, and a test that only covered one would let the other keep the old
        answer -- with the symptom that whether you got a correct exit code
        depended on how far config resolution had got.
        """
        from automated_security_helper.config.ash_config import AshConfig

        opts = _opts(tmp_path)
        results = MagicMock()
        results.sarif = None
        results.ash_config = AshConfig(project_name="gate-default-test")

        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[_metric("syft", ScannerStatus.MISSING.value)],
        ):
            code = _compute_exit_code(results, opts)

        assert code == 1

    def test_skipped_scanners_never_trip_the_gate(self, tmp_path):
        """SKIPPED is "not selected", which is how a shard excludes its siblings.

        Every shard of an n-way split records n-1 scanner sets as SKIPPED. If
        SKIPPED counted as incomplete, turning the knob on would fail all n
        shards of a healthy sharded scan.
        """
        opts = _opts(tmp_path, fail_on_incomplete_scanners=True)
        results = MagicMock()
        results.sarif = None

        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[
                _metric("bandit", ScannerStatus.PASSED.value),
                _metric("semgrep", ScannerStatus.SKIPPED.value),
                _metric("checkov", ScannerStatus.SKIPPED.value),
            ],
        ):
            code = _compute_exit_code(results, opts)

        assert code == 0, "SKIPPED means deliberately not selected, not incomplete"

    def test_all_scanners_complete_exits_zero(self, tmp_path):
        """The knob on, nothing incomplete, nothing found: still a clean scan."""
        opts = _opts(tmp_path, fail_on_incomplete_scanners=True)
        results = MagicMock()
        results.sarif = None

        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[
                _metric("bandit", ScannerStatus.PASSED.value),
                _metric("semgrep", ScannerStatus.PASSED.value),
            ],
        ):
            code = _compute_exit_code(results, opts)

        assert code == 0


class TestIndependenceFromFailOnFindings:
    """The two knobs answer different questions and must not gate each other."""

    def test_fail_on_findings_false_still_reports_an_incomplete_scan(self, tmp_path):
        """``fail_on_findings: false`` must not disable the completeness gate.

        ``_compute_exit_code`` returns 0 early when findings-gating is off. A
        completeness check placed after that return would be dead for exactly
        the operators who set it.
        """
        opts = _opts(tmp_path, fail_on_findings=False, fail_on_incomplete_scanners=True)
        results = MagicMock()
        results.sarif = None

        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[_metric("grype", ScannerStatus.ERROR.value, actionable=0)],
        ):
            code = _compute_exit_code(results, opts)

        assert code == 1, (
            "fail_on_findings governs findings, not whether the scan ran; the "
            "completeness gate has to be checked before the early return"
        )

    def test_incomplete_scan_outranks_actionable_findings(self, tmp_path):
        """Both conditions true reports 1, not 2.

        1 is ASH's "error during execution" code and the honest verdict: the
        findings that were reported are real, but the set is known to be
        partial. Reporting 2 would tell a reviewer that fixing the listed
        findings clears the scan, when several scanners never ran.
        """
        opts = _opts(tmp_path, fail_on_incomplete_scanners=True)
        results = MagicMock()
        results.sarif = None

        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[
                _metric("bandit", ScannerStatus.FAILED.value, actionable=7),
                _metric("cdk-nag", ScannerStatus.MISSING.value),
            ],
        ):
            code = _compute_exit_code(results, opts)

        assert code == 1

    def test_findings_alone_still_exit_two_with_the_knob_on(self, tmp_path):
        """Turning the knob on must not disturb the existing findings verdict."""
        opts = _opts(tmp_path, fail_on_incomplete_scanners=True)
        results = MagicMock()
        results.sarif = None

        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[_metric("bandit", ScannerStatus.FAILED.value, actionable=3)],
        ):
            code = _compute_exit_code(results, opts)

        assert code == 2


class TestResolutionPrecedence:
    """CLI beats config beats off, mirroring ``fail_on_findings``."""

    def test_config_value_applies_when_cli_unset(self, tmp_path):
        opts = _opts(tmp_path)
        results = MagicMock()
        results.sarif = None

        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[_metric("syft", ScannerStatus.MISSING.value)],
        ):
            code = _compute_exit_code(
                results, opts, config_fail_on_incomplete_scanners=True
            )

        assert code == 1

    def test_cli_false_overrides_config_true(self, tmp_path):
        """An operator who passes ``--no-fail-on-incomplete-scanners`` wins."""
        opts = _opts(tmp_path, fail_on_incomplete_scanners=False)
        results = MagicMock()
        results.sarif = None

        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[_metric("syft", ScannerStatus.MISSING.value)],
        ):
            code = _compute_exit_code(
                results, opts, config_fail_on_incomplete_scanners=True
            )

        assert code == 0

    def test_cli_true_overrides_config_false(self, tmp_path):
        """``--fail-on-incomplete-scanners`` beats ``: false`` in the config."""
        opts = _opts(tmp_path, fail_on_incomplete_scanners=True)
        results = MagicMock()
        results.sarif = None

        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[_metric("syft", ScannerStatus.MISSING.value)],
        ):
            code = _compute_exit_code(
                results, opts, config_fail_on_incomplete_scanners=False
            )

        assert code == 1


class TestReadsTheAuthoritativeSignals:
    """Two fields look like they carry this signal and do not. Built from real
    models rather than status mocks, because the point is which field the gate
    ends up reading -- a mocked status list would answer that by construction.

    Both cases deliberately set their two signals to DISAGREE. A case where they
    agree cannot tell you which one the gate leans on, and that blind spot is why
    the wrong field looked interchangeable in the first place.
    """

    @staticmethod
    def _model_with(scanner: str, status: ScannerStatus, source_status: str):
        """A model whose two per-scanner status fields disagree.

        Measured shape: on a run where bandit found two HIGH findings,
        ``scanner_results.bandit.status`` was FAILED while
        ``additional_reports.bandit.source.status`` was PASSED.
        ``ScannerStatisticsCalculator.get_scanner_status_info`` is an if/elif
        chain that reaches ``additional_reports[name]["source"]`` only when the
        scanner is absent from ``scanner_results``, so the entry below has to be
        present for the precedence to be exercised at all.
        """
        # AshConfig is imported first on purpose: AshAggregatedResults declares
        # ash_config as a forward reference, and until AshConfig is defined the
        # model has no validator and construction raises PydanticUserError. Same
        # dependency cli/merge.py documents at module scope.
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.models.asharp_model import (
            AshAggregatedResults,
            ScannerStatusInfo,
        )

        model = AshAggregatedResults()
        model.ash_config = AshConfig(project_name="gate-signal-test")
        model.scanner_results[scanner] = ScannerStatusInfo(
            status=status,
            excluded=False,
            dependencies_satisfied=status is not ScannerStatus.MISSING,
        )
        model.additional_reports[scanner] = {
            "source": {"scanner_name": scanner, "status": source_status}
        }
        return model

    def test_reads_scanner_results_not_additional_reports(self, tmp_path):
        """An ERROR in ``scanner_results`` is a fault even when
        ``additional_reports.source`` says PASSED.

        A gate reading the wrong one accepts a scan that did not run. Nothing is
        patched here: the status comes out of the real
        ``get_unified_scanner_metrics``.
        """
        model = self._model_with("bandit", ScannerStatus.ERROR, "PASSED")

        from automated_security_helper.interactions.run_ash_scan import (
            incomplete_scanners,
        )

        assert incomplete_scanners(model) == [("bandit", "ERROR")], (
            "the gate must read scanner_results.<name>.status; the "
            "additional_reports source marker said PASSED on this same model"
        )

        opts = _opts(tmp_path, fail_on_incomplete_scanners=True)
        assert _compute_exit_code(model, opts) == 1

    def test_missing_in_scanner_results_is_a_fault_too(self, tmp_path):
        """The same precedence, for the MISSING half of the fault set."""
        model = self._model_with("cdk-nag", ScannerStatus.MISSING, "PASSED")

        opts = _opts(tmp_path, fail_on_incomplete_scanners=True)
        assert _compute_exit_code(model, opts) == 1

    def test_cannot_be_fooled_by_a_clean_completion_validation_block(self, tmp_path):
        """``validation_summary.*.has_issues`` must not be able to suppress this.

        Measured on a run with four scanner tools absent: ``summary_stats.missing``
        was 4 while ``execution_completion_validation`` reported
        ``{expected_count: 1, completed_count: 1, missing_count: 0,
        completion_rate: 1.0, has_issues: false}``. "expected" counts only the
        scanners actually dispatched, so a MISSING scanner never enters the
        expected set and cannot register as absent from it -- the field
        under-reports exactly the condition it appears to report.

        This model carries that clean block alongside a genuine MISSING scanner.
        The gate reads neither ``validation_summary`` nor ``summary_stats``, so it
        is structurally immune; the test pins that rather than trusting it.
        """
        model = self._model_with("cdk-nag", ScannerStatus.MISSING, "PASSED")
        # metadata.validation_summary, not a root-level field: ScanPhase writes it
        # onto ReportMetadata by setattr, which works because ReportMetadata is
        # declared extra="allow" (see scan_phase.py's validation_summary blocks).
        model.metadata.validation_summary = {
            "execution_completion_validation": {
                "expected_count": 1,
                "completed_count": 1,
                "missing_count": 0,
                "completion_rate": 1.0,
                "has_issues": False,
            }
        }

        opts = _opts(tmp_path, fail_on_incomplete_scanners=True)
        assert _compute_exit_code(model, opts) == 1, (
            "a clean completion-validation block must not suppress a real "
            "MISSING scanner"
        )

    def test_error_fires_when_every_summary_stats_counter_says_nothing_is_wrong(
        self, tmp_path
    ):
        """The case that separates this fix from a ``summary_stats``-keyed one.

        ERROR scanners are absent from every ``summary_stats`` counter -- not
        ``failed``, not ``passed``, not ``missing``, not ``skipped``. Measured
        twice on different infrastructure. A 4-shard pipeline with two arms and
        one variable changed (shard 3's scanners forced into ERROR)::

            arm A (control) merge exit 2  actionable=16 failed=1 passed=9 missing=0
            arm B (broken)  merge exit 0  actionable=0  failed=0 passed=8 missing=0

        Arm A proves the tree really holds 16 critical findings, so arm B's zero
        is a loss. Arm A accounts for 10 scanners, arm B for 8.

        Reproduced locally by a different mechanism -- ``UV_CACHE_DIR`` pointed at
        a path whose parent is not a directory, which fails uv tool installs --
        giving ``bandit=ERROR checkov=ERROR`` with
        ``passed=0 failed=0 missing=0 skipped=8`` and a default ``ash scan`` exit
        of 0.

        So this model sets ``missing`` to 0 deliberately. A gate keyed on
        ``summary_stats.missing`` reads 0 and returns 0; the per-scanner read
        returns 1. Every other test here would pass under either implementation.
        """
        model = self._model_with("bandit", ScannerStatus.ERROR, "PASSED")
        model.metadata.summary_stats.passed = 0
        model.metadata.summary_stats.failed = 0
        model.metadata.summary_stats.missing = 0
        model.metadata.summary_stats.skipped = 8

        assert model.metadata.summary_stats.missing == 0, (
            "the fixture must present a clean missing counter, or this test cannot "
            "distinguish the two implementations"
        )

        opts = _opts(tmp_path, fail_on_incomplete_scanners=True)
        assert _compute_exit_code(model, opts) == 1, (
            "an ERROR scanner must fail the gate even when every summary_stats "
            "counter reads clean; ERROR appears in none of them"
        )

    def test_summary_stats_now_counts_error_and_the_gate_still_ignores_it(self):
        """The revisit this test's earlier form asked for, answered both ways.

        It used to assert ``"error" not in SummaryStats.model_fields`` with the
        note "if SummaryStats grows an error counter, revisit whether the gate
        should read it". It has grown one, so here is the answer: the counter is
        worth having and the gate still must not read it.

        Worth having, because a scanner that ran and failed appeared in none of
        passed/failed/missing/skipped, so the counters summed to less than the
        scanner count on exactly the runs where that mattered, and anything
        deriving a verdict from those totals -- a dashboard, a CI gate, a reviewer
        skimming the report -- read a tally that silently excluded the worst
        outcomes. The five counters now partition the set, which this asserts by
        arithmetic rather than by naming fields.

        And still not read by the gate, because a count cannot name the scanner.
        The failure message has to say *which* scanner did not complete or it sends
        an operator to the wrong place, and ``incomplete_scanners`` reading
        per-scanner status is what supplies the name. A count would also reintroduce
        the coupling this whole file exists to break: two readers of the same state,
        one of which can be right while the other is wrong.
        """
        from automated_security_helper.models.asharp_model import SummaryStats

        assert "error" in SummaryStats.model_fields, (
            "ERROR needs a counter of its own; without one the other four sum to "
            "fewer than the scanners in the run and every total reads clean"
        )

        buckets = ("passed", "failed", "missing", "skipped", "error")
        stats = SummaryStats(passed=3, failed=1, missing=2, skipped=3, error=1)
        assert sum(getattr(stats, b) for b in buckets) == 10

        model = self._model_with("grype", ScannerStatus.ERROR, "PASSED")

        from automated_security_helper.interactions.run_ash_scan import (
            incomplete_scanners,
        )

        # Named, not counted. This is the property a counter cannot provide.
        assert incomplete_scanners(model) == [("grype", "ERROR")]


class TestIncompleteScannerReport:
    """The failure has to name which scanners and which status.

    "exit 1" on its own sends an operator to the wrong place: the generic exit-1
    message in ``run_ash_scan`` says an exception occurred, which is not what
    happened.
    """

    def test_helper_lists_only_incomplete_scanners_with_statuses(self):
        from automated_security_helper.interactions.run_ash_scan import (
            incomplete_scanners,
        )

        results = MagicMock()
        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[
                _metric("bandit", ScannerStatus.PASSED.value),
                _metric("cdk-nag", ScannerStatus.MISSING.value),
                _metric("semgrep", ScannerStatus.SKIPPED.value),
                _metric("grype", ScannerStatus.ERROR.value),
            ],
        ):
            listed = incomplete_scanners(results)

        assert listed == [
            ("cdk-nag", ScannerStatus.MISSING.value),
            ("grype", ScannerStatus.ERROR.value),
        ]

    def test_helper_is_empty_for_no_results(self):
        from automated_security_helper.interactions.run_ash_scan import (
            incomplete_scanners,
        )

        assert incomplete_scanners(None) == []


class TestStatusClassificationFailsClosed:
    """A status this version does not recognise is not evidence a scanner ran.

    The classification used to be a denylist -- ``status in {ERROR, MISSING}`` --
    which makes every status the list does not name count as complete. That is the
    wrong default for a completeness check, and it is reachable rather than
    hypothetical: ``ash merge`` reads shard results written by whatever ASH produced
    them, so a mixed-version fan-out can hand this code a status string that is not
    in this version's enum. A denylist reports that shard as complete.

    Inverted to an allowlist of the three statuses that mean the scanner's outcome is
    known. Anything else is incomplete, so an unrecognised status fails loudly
    instead of passing quietly.
    """

    def test_an_unrecognised_status_is_reported_incomplete(self):
        from automated_security_helper.interactions.run_ash_scan import (
            incomplete_scanners,
        )

        results = MagicMock()
        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[
                _metric("bandit", ScannerStatus.PASSED.value),
                _metric("semgrep", "PARTIALLY_COMPLETED"),
            ],
        ):
            listed = incomplete_scanners(results)

        assert listed == [("semgrep", "PARTIALLY_COMPLETED")], (
            "a status from another ASH version has to be treated as incomplete; "
            "counting it as complete is how a partial scan reads as a whole one"
        )

    def test_the_two_status_sets_partition_the_enum(self):
        """Neither set may drift from the enum, in either direction.

        The complete set is spelled out and the incomplete set is derived as its
        complement, so a member added to ``ScannerStatus`` becomes incomplete by
        construction -- fail-closed -- rather than defaulting to complete. This
        asserts the two facts that makes rest on: they are disjoint, and together
        they cover every member.
        """
        from automated_security_helper.interactions.run_ash_scan import (
            _COMPLETE_SCANNER_STATUSES,
            _INCOMPLETE_SCANNER_STATUSES,
        )

        every = {member.value for member in ScannerStatus}
        assert _COMPLETE_SCANNER_STATUSES | _INCOMPLETE_SCANNER_STATUSES == every
        assert not (_COMPLETE_SCANNER_STATUSES & _INCOMPLETE_SCANNER_STATUSES)

    def test_skipped_is_on_the_complete_side(self):
        """The one classification that is a decision rather than a definition.

        SKIPPED means the scanner was not selected, and that is how sharding divides
        work: each shard of an n-way split records the other shards' scanners as
        SKIPPED. Treating it as incomplete would fail every shard of a healthy
        sharded scan. Pinned separately from the partition above, which would still
        hold with SKIPPED on either side.
        """
        from automated_security_helper.interactions.run_ash_scan import (
            _COMPLETE_SCANNER_STATUSES,
        )

        assert ScannerStatus.SKIPPED.value in _COMPLETE_SCANNER_STATUSES
        assert _COMPLETE_SCANNER_STATUSES == {"PASSED", "FAILED", "SKIPPED"}


class TestConfigFileResolution:
    """The YAML field has to be readable without building the orchestrator."""

    def test_reads_fail_on_incomplete_scanners_from_config_file(self, tmp_path):
        from automated_security_helper.interactions.run_ash_scan import (
            _resolve_config_fail_on_incomplete_scanners,
        )

        source = tmp_path / "src"
        source.mkdir()
        (source / ".ash.yaml").write_text(
            "project_name: gate-test\nfail_on_incomplete_scanners: true\n",
            encoding="utf-8",
        )

        opts = ScanOptions(source_dir=source, output_dir=tmp_path / "out")
        assert _resolve_config_fail_on_incomplete_scanners(opts) is True

    def test_absent_field_resolves_to_the_models_default(self, tmp_path):
        from automated_security_helper.interactions.run_ash_scan import (
            _resolve_config_fail_on_incomplete_scanners,
        )

        source = tmp_path / "src"
        source.mkdir()
        (source / ".ash.yaml").write_text("project_name: gate-test\n", encoding="utf-8")

        opts = ScanOptions(source_dir=source, output_dir=tmp_path / "out")
        assert _resolve_config_fail_on_incomplete_scanners(opts) is True

    def test_reads_an_explicit_false_from_the_config_file(self, tmp_path):
        """An operator who wrote ``false`` gets ``false``, not the default.

        Worth its own test now that the default is True: without it, a bug that
        made this function ignore the file and return the model default would be
        invisible -- ``test_absent_field_resolves_to_the_models_default`` would
        still pass, and so would every other test here. The opt-out is the only
        way an environment that has decided a partial scan is acceptable can say
        so, so it has to be the one thing that cannot silently stop working.
        """
        from automated_security_helper.interactions.run_ash_scan import (
            _resolve_config_fail_on_incomplete_scanners,
        )

        source = tmp_path / "src"
        source.mkdir()
        (source / ".ash.yaml").write_text(
            "project_name: gate-test\nfail_on_incomplete_scanners: false\n",
            encoding="utf-8",
        )

        opts = ScanOptions(source_dir=source, output_dir=tmp_path / "out")
        assert _resolve_config_fail_on_incomplete_scanners(opts) is False

    def test_no_config_file_resolves_to_none(self, tmp_path):
        from automated_security_helper.interactions.run_ash_scan import (
            _resolve_config_fail_on_incomplete_scanners,
        )

        source = tmp_path / "src"
        source.mkdir()
        opts = ScanOptions(source_dir=source, output_dir=tmp_path / "out")
        assert _resolve_config_fail_on_incomplete_scanners(opts) is None


class TestConfigModelAndValidator:
    """The field has to exist on the model and be accepted by ``ash config``."""

    def test_config_field_defaults_to_true(self):
        from automated_security_helper.config.ash_config import AshConfig

        assert AshConfig(project_name="x").fail_on_incomplete_scanners is True

    def test_the_model_default_and_the_resolver_fallback_agree(self, tmp_path):
        """Two answers to one question must not be able to disagree.

        ``_resolve_fail_on_incomplete_scanners`` ends in a literal rather than
        reading the model, so the model default and that literal are two
        independent copies of the same decision. When they disagreed, which one you
        got depended on whether a config model had been built by the time the exit
        code was computed -- so the same scan could be gated or not gated depending
        on how it was invoked. This test is what makes changing one of them without
        the other a failure rather than a subtle inconsistency.
        """
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.interactions.run_ash_scan import (
            _resolve_fail_on_incomplete_scanners,
        )

        # No opts value, no config value, and a results object carrying nothing
        # bool-shaped, so resolution reaches the final fallback literal.
        bare = MagicMock()
        bare.ash_config = None
        fallback = _resolve_fail_on_incomplete_scanners(bare, _opts(tmp_path), None)

        assert fallback is AshConfig(project_name="x").fail_on_incomplete_scanners

    def test_validator_accepts_the_new_top_level_field(self):
        from automated_security_helper.config.config_validator import ConfigValidator

        assert (
            "fail_on_incomplete_scanners" in ConfigValidator.VALID_TOP_LEVEL_FIELDS
        ), (
            "an unlisted top-level field makes 'ash config validate' reject a "
            "config that 'ash scan' accepts"
        )


class TestContainerModeForwarding:
    """The container runs this same CLI, so the flag has to reach it."""

    @pytest.mark.parametrize(
        "value,expected_flag",
        [
            (True, "--fail-on-incomplete-scanners"),
            (False, "--no-fail-on-incomplete-scanners"),
        ],
    )
    def test_flag_is_forwarded_into_the_container(self, tmp_path, value, expected_flag):
        from automated_security_helper.core.enums import ExecutionStrategy
        from automated_security_helper.interactions.run_ash_container import (
            _assemble_run_command,
        )

        cmd = _assemble_run_command(
            oci_command_prefix=[],
            resolved_oci_runner="finch",
            image_name="ash:latest",
            source_dir=tmp_path / "src",
            output_dir=tmp_path / "out",
            offline=False,
            debug=False,
            color=False,
            quiet=True,
            progress=False,
            verbose=False,
            simple=False,
            python_based_plugins_only=False,
            cleanup=False,
            inspect=False,
            fail_on_findings=None,
            fail_on_incomplete_scanners=value,
            phases=[],
            scanners=[],
            exclude_scanners=[],
            output_formats=[],
            config=None,
            config_overrides=[],
            existing_results=None,
            ash_plugin_modules=[],
            strategy=ExecutionStrategy.PARALLEL,
            ctx=None,
        )

        assert expected_flag in cmd

    def test_unset_forwards_neither_flag(self, tmp_path):
        from automated_security_helper.core.enums import ExecutionStrategy
        from automated_security_helper.interactions.run_ash_container import (
            _assemble_run_command,
        )

        cmd = _assemble_run_command(
            oci_command_prefix=[],
            resolved_oci_runner="finch",
            image_name="ash:latest",
            source_dir=tmp_path / "src",
            output_dir=tmp_path / "out",
            offline=False,
            debug=False,
            color=False,
            quiet=True,
            progress=False,
            verbose=False,
            simple=False,
            python_based_plugins_only=False,
            cleanup=False,
            inspect=False,
            fail_on_findings=None,
            fail_on_incomplete_scanners=None,
            phases=[],
            scanners=[],
            exclude_scanners=[],
            output_formats=[],
            config=None,
            config_overrides=[],
            existing_results=None,
            ash_plugin_modules=[],
            strategy=ExecutionStrategy.PARALLEL,
            ctx=None,
        )

        assert "--fail-on-incomplete-scanners" not in cmd
        assert "--no-fail-on-incomplete-scanners" not in cmd


class TestRunAshScanPlumbing:
    """``run_ash_scan`` has to hand the resolved value to ``_compute_exit_code``."""

    def test_config_value_reaches_compute_exit_code(self, tmp_path):
        from automated_security_helper.interactions import run_ash_scan as mod
        from automated_security_helper.models.asharp_model import AshAggregatedResults

        results = MagicMock(spec=AshAggregatedResults)
        results.sarif = None
        captured: dict = {}

        def spy(results_arg, opts_arg, *args, **kwargs):
            captured["kwargs"] = kwargs
            captured["args"] = args
            return 0

        with patch.object(
            mod, "_resolve_config_fail_on_incomplete_scanners", return_value=True
        ):
            with patch.object(
                mod, "_resolve_config_fail_on_findings", return_value=None
            ):
                with patch.object(mod, "_run_container_mode", return_value=results):
                    with patch.object(mod, "_compute_exit_code", side_effect=spy):
                        with patch.object(
                            mod, "_setup_logger", return_value=MagicMock()
                        ):
                            mod.run_ash_scan(
                                source_dir=tmp_path / "src",
                                output_dir=tmp_path / "out",
                                mode=RunMode.container,
                                show_summary=False,
                            )

        assert (
            captured["kwargs"].get("config_fail_on_incomplete_scanners") is True
            or True in captured["args"]
        ), (
            "the resolved config value must reach _compute_exit_code, or a YAML "
            f"setting is silently ignored; got args={captured['args']} "
            f"kwargs={captured['kwargs']}"
        )
