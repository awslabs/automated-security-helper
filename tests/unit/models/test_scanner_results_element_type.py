"""``scanner_results`` holds ScannerTargetStatusInfo, and everything that reads it agrees.

WHY THIS FILE EXISTS. ``AshAggregatedResults.scanner_results`` is declared
``Dict[str, ScannerTargetStatusInfo]`` and the published schema agrees
(``AshAggregatedResults.json``: ``additionalProperties -> ScannerTargetStatusInfo``).
Five writers in the scan phase and scanner validation stored ``ScannerStatusInfo``
there instead. Nothing caught it, for two reasons worth recording:

* pydantic validates a field on assignment to the *field*, not on mutation of a dict
  the field already holds, so ``scanner_results[name] = WrongType()`` is silent; and
* both classes set ``extra="allow"``, so a later write of an undeclared attribute onto
  the wrong shape also succeeds silently.

Six fields are declared on ``ScannerTargetStatusInfo`` and not on
``ScannerStatusInfo`` -- ``finding_count``, ``actionable_finding_count``,
``suppressed_finding_count``, ``severity_counts``, ``exit_code``, ``duration``. Reading
any of them off the wrong shape raises ``AttributeError`` far from the write, inside a
reporter. That is how it surfaced: an integration test built the shape the scan phase
builds, called a reporter directly, and died in
``_apply_suppression_side_effects``.

WHAT THESE TESTS PIN, AND WHAT THEY DO NOT. They pin the element type at the writers,
and that the read paths tolerate the shapes that legitimately reach them. They do not
pin that a full scan produces consistent metrics -- the engine normalises
``scanner_results`` inside its ``case "report"`` arm before any reporter runs, so the
end-to-end path was never broken and no test here should claim it was.
"""

import ast
from pathlib import Path

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerSeverityCount,
    ScannerStatusInfo,
    ScannerTargetStatusInfo,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]

# The asymmetry the whole defect rests on.
TARGET_ONLY_FIELDS = (
    "finding_count",
    "actionable_finding_count",
    "suppressed_finding_count",
    "severity_counts",
    "exit_code",
    "duration",
)


def test_the_six_target_only_fields_are_still_target_only():
    """If this drifts, the rest of this file is testing the wrong asymmetry."""
    target = set(ScannerTargetStatusInfo.model_fields)
    scanner = set(ScannerStatusInfo.model_fields)
    assert set(TARGET_ONLY_FIELDS) == target - scanner, (
        "the field asymmetry between the two classes changed; update "
        f"TARGET_ONLY_FIELDS. target-only is now {sorted(target - scanner)}"
    )


def test_every_target_only_field_is_readable_on_the_declared_type():
    """The positive half: the declared type answers all six without a guard."""
    entry = ScannerTargetStatusInfo()
    for name in TARGET_ONLY_FIELDS:
        getattr(entry, name)


def test_none_of_them_is_readable_on_the_wrong_shape():
    """The control for the above: the wrong shape raises on every one of the six.

    This is what makes the writer assertions below load-bearing rather than
    decorative -- if ScannerStatusInfo happened to carry these fields, storing it in
    scanner_results would be harmless and none of this would matter.
    """
    wrong = ScannerStatusInfo()
    for name in TARGET_ONLY_FIELDS:
        with pytest.raises(AttributeError):
            getattr(wrong, name)


class TestTheWritersHonourTheDeclaredType:
    """Each scan-phase state that writes a scanner_results entry writes the right type.

    Asserted on the constructed object rather than by driving the phase, because the
    four write sites sit deep inside dependency-resolution branches that need a
    registered plugin set to reach. The value being pinned is the element type, and
    the constructor is where that is decided.
    """

    @pytest.mark.parametrize(
        "kwargs",
        [
            # excluded during filtering, and the excluded-scanner helper
            {
                "status": ScannerStatus.SKIPPED,
                "excluded": True,
                "dependencies_satisfied": True,
            },
            # missing dependencies
            {
                "status": ScannerStatus.MISSING,
                "dependencies_satisfied": False,
                "excluded": False,
            },
            # unclassified
            {
                "status": ScannerStatus.MISSING,
                "dependencies_satisfied": True,
                "excluded": False,
            },
        ],
    )
    def test_each_writer_shape_constructs_the_declared_type(self, kwargs):
        entry = ScannerTargetStatusInfo(**kwargs)
        assert isinstance(entry, ScannerTargetStatusInfo)
        # and the suppression path can run against it straight away
        assert entry.suppressed_finding_count == 0
        assert entry.severity_counts.suppressed == 0

    def test_the_fields_the_writers_pass_exist_on_both_classes(self):
        """Why the swap was a drop-in: every field they pass is on both classes.

        If a writer ever passes a scanner-level-only field, the swap stops being
        safe and this test is where that shows up.
        """
        passed = {"status", "excluded", "dependencies_satisfied"}
        assert passed <= set(ScannerTargetStatusInfo.model_fields)
        assert passed <= set(ScannerStatusInfo.model_fields)


class TestSuppressionSideEffectsAcceptWhatReachesThem:
    """``_apply_suppression_side_effects`` handles every shape that can arrive."""

    @staticmethod
    def _model(entry):
        model = AshAggregatedResults()
        model.scanner_results = {"bandit": entry}
        return model

    def test_the_declared_type_is_incremented_in_place(self):
        model = self._model(ScannerTargetStatusInfo())
        model._apply_suppression_side_effects("bandit")
        assert model.scanner_results["bandit"].suppressed_finding_count == 1
        assert model.scanner_results["bandit"].severity_counts.suppressed == 1

    def test_a_dict_from_json_is_validated_then_incremented(self):
        """dicts are the expected non-model shape: JSON round-trips produce them."""
        model = self._model({"status": "PASSED", "suppressed_finding_count": 4})
        model._apply_suppression_side_effects("bandit")
        entry = model.scanner_results["bandit"]
        assert isinstance(entry, ScannerTargetStatusInfo)
        assert entry.suppressed_finding_count == 5

    def test_a_wrong_model_is_normalised_rather_than_raising(self, caplog):
        """The shape the writers used to produce, which used to raise here.

        Normalised rather than raised on so that an older results document, or a
        writer added in future, degrades to a warning instead of taking a reporter
        down. The warning is asserted because silent absorption is the failure mode
        this file exists to prevent.
        """
        model = self._model(
            ScannerStatusInfo(status=ScannerStatus.SKIPPED, excluded=True)
        )
        model._apply_suppression_side_effects("bandit")
        entry = model.scanner_results["bandit"]
        assert isinstance(entry, ScannerTargetStatusInfo)
        assert entry.suppressed_finding_count == 1
        assert entry.excluded is True, "normalising must not drop the shared fields"
        assert any(
            "not ScannerTargetStatusInfo" in r.message % r.args
            if r.args
            else "not ScannerTargetStatusInfo" in r.message
            for r in caplog.records
        ) or any(
            "not ScannerTargetStatusInfo" in r.getMessage() for r in caplog.records
        ), (
            "normalising a wrong-typed entry must say so; absorbing it silently is "
            "how the original defect stayed hidden"
        )

    def test_a_wrong_model_with_unset_fields_normalises(self):
        """The shapes disagree on optionality, not only on which fields exist.

        ``ScannerStatusInfo`` declares ``status: ScannerStatus | None = None`` while
        ``ScannerTargetStatusInfo`` declares ``status: ScannerStatus``. Forwarding the
        dump verbatim therefore sent an explicit ``None`` into a non-optional field and
        traded the original AttributeError for a ValidationError -- a different
        failure, not a fix. Unset keys are dropped so the target's defaults apply.

        This is the default-constructed case, which is exactly what the scan phase
        used to store, so it is the one that has to work.
        """
        model = self._model(ScannerStatusInfo())
        assert model.scanner_results["bandit"].status is None, (
            "precondition: the source shape must leave status unset, or this test "
            "is not exercising the optionality mismatch"
        )
        model._apply_suppression_side_effects("bandit")
        entry = model.scanner_results["bandit"]
        assert isinstance(entry, ScannerTargetStatusInfo)
        assert entry.status == ScannerStatus.PASSED, "the target's default should apply"
        assert entry.suppressed_finding_count == 1

    def test_a_missing_key_is_a_no_op(self):
        model = AshAggregatedResults()
        model.scanner_results = {}
        model._apply_suppression_side_effects("absent")  # must not raise

    def test_a_none_entry_is_a_no_op(self):
        model = self._model(None)
        model._apply_suppression_side_effects("bandit")  # must not raise


class TestNoWriterStoresTheScannerLevelShape:
    """Source gate: nothing may assign ScannerStatusInfo into scanner_results.

    The constructor tests above cannot catch a writer regression -- they assert that
    ``ScannerTargetStatusInfo(...)`` behaves, which stays true however the writers
    change. This scans the source instead, the same way
    ``test_environ_mutation_fix.py`` scans for ``os.environ`` mutation, because the
    property being defended is "no writer does X" and that is a statement about the
    source rather than about any value.
    """

    WRITERS = (
        "automated_security_helper/core/phases/scan_phase.py",
        "automated_security_helper/models/scanner_validation.py",
    )

    @staticmethod
    def _assignments_into_scanner_results(tree):
        """Yield (lineno, constructed_name) for ``...scanner_results[k] = Name(...)``."""
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for tgt in node.targets:
                if not (
                    isinstance(tgt, ast.Subscript)
                    and isinstance(tgt.value, ast.Attribute)
                    and tgt.value.attr == "scanner_results"
                ):
                    continue
                val = node.value
                if isinstance(val, ast.Call) and isinstance(val.func, ast.Name):
                    yield node.lineno, val.func.id

    @pytest.mark.parametrize("rel", WRITERS)
    def test_no_scanner_status_info_is_stored_in_scanner_results(self, rel):
        path = _REPO_ROOT / rel
        tree = ast.parse(path.read_text(encoding="utf-8"))
        offenders = [
            (line, name)
            for line, name in self._assignments_into_scanner_results(tree)
            if name == "ScannerStatusInfo"
        ]
        assert not offenders, (
            f"{rel} stores ScannerStatusInfo into scanner_results at "
            f"{[line for line, _ in offenders]}. That dict is declared "
            "Dict[str, ScannerTargetStatusInfo] and the published schema agrees; "
            "six fields read off entries are not declared on ScannerStatusInfo."
        )

    def test_the_gate_can_see_an_assignment_at_all(self):
        """Control for the gate: prove the AST walk finds the pattern it looks for.

        Without this, a walk that silently matched nothing would pass both files
        forever -- absence of offenders and absence of vision look identical.
        """
        tree = ast.parse(
            "def f(agg):\n    agg.scanner_results['x'] = ScannerStatusInfo(status=1)\n"
        )
        found = list(self._assignments_into_scanner_results(tree))
        assert found == [(2, "ScannerStatusInfo")], found

    def test_the_real_writers_are_visible_to_the_gate(self):
        """And that the walk sees the actual writers, not just a synthetic snippet."""
        seen = {}
        for rel in self.WRITERS:
            tree = ast.parse((_REPO_ROOT / rel).read_text(encoding="utf-8"))
            seen[rel] = list(self._assignments_into_scanner_results(tree))
        assert any(seen.values()), (
            "the gate found no scanner_results assignment in either writer, so it "
            f"is not looking where it thinks: {seen}"
        )


def test_the_consistency_check_counts_the_declared_element_type():
    """``_validate_metrics_consistency`` must recognise ScannerTargetStatusInfo.

    Its shape dispatch knew two forms -- the legacy scanner-level one with
    source/converted, and the unified ScannerMetrics row. The declared element type
    matched neither, so entries fell to a debug-log else arm and added nothing,
    leaving the totals at zero and warning about differences that were artefacts of
    the missing branch. Since unified_metrics writes exactly that type before every
    report, the check was reporting on a shape it could not read.
    """
    from automated_security_helper.core.phases.scan_phase import ScanPhase

    model = AshAggregatedResults()
    model.scanner_results = {
        "bandit": ScannerTargetStatusInfo(
            severity_counts=ScannerSeverityCount(critical=2, high=1, suppressed=3),
            finding_count=3,
            actionable_finding_count=3,
        )
    }
    stats = model.metadata.summary_stats
    stats.critical, stats.high, stats.suppressed = 2, 1, 3
    stats.medium = stats.low = stats.info = 0
    stats.total, stats.actionable = 3, 3

    records = []

    class _Log:
        def warning(self, msg, *a, **k):
            records.append(str(msg))

        def debug(self, *a, **k):
            pass

        def error(self, *a, **k):
            records.append("ERROR")

    import automated_security_helper.core.phases.scan_phase as sp

    original = sp.ASH_LOGGER
    sp.ASH_LOGGER = _Log()
    try:
        ScanPhase._validate_metrics_consistency(object.__new__(ScanPhase), model)
    finally:
        sp.ASH_LOGGER = original

    assert not records, (
        "the consistency check disagreed with summary_stats that match the entry "
        f"exactly, so it did not read the entry: {records}"
    )


def test_severity_count_declares_suppressed_so_the_old_hasattr_was_dead():
    """The removed ``hasattr(severity_counts, "suppressed")`` could not be False.

    Recorded as a test because the guard read as defensive and was not: with
    ``extra="allow"`` a hasattr guard around the increment would have created an
    undeclared attribute on a wrong-shaped object instead of failing, which is worse
    than either raising or normalising.
    """
    assert "suppressed" in ScannerSeverityCount.model_fields
    assert ScannerSeverityCount().suppressed == 0
