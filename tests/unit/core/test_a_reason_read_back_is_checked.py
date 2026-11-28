"""A reason read back from a results file is checked before anything uses it.

The scan phase writes a reason through ``FailureReason``, which refuses a sentence
that is not a short reason and a code that is not written as one. A results file
is text nobody here wrote: an ERROR row or per-target report that carries a path in
``error_reason``, or a malformed ``error_reason_code``, would otherwise be copied
onto the rebuilt row, into ``ash.flat.json`` and into the YAML report, where only
``get_scanners_not_run`` checked it again. The pair is checked where it is read
(``unified_metrics._reason_pair``) and again where the flat rows are built.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core import unified_metrics
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.unified_metrics import (
    get_unified_scanner_metrics,
    populate_metrics_from_unified_source,
    recorded_error_reason,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)

pytestmark = pytest.mark.unit

FIT = ("timed_out", "it timed out after 300 s and was killed")

#: Each is a pair a results file could hold that the scan phase would never write.
UNFIT = [
    pytest.param(
        ("timed_out", "could not read /home/someone/out/x.sarif"), id="a-path"
    ),
    pytest.param(("timed_out", "could not read file:///etc/x"), id="a-file-uri"),
    pytest.param(("timed_out", "could not read C:\\scan\\out"), id="a-drive-path"),
    pytest.param(("timed_out", "line one\nline two"), id="two-lines"),
    pytest.param(("timed_out", "x" * 201), id="over-the-limit"),
    pytest.param(("Not A Code!", "it timed out"), id="a-malformed-code"),
    pytest.param(("../../etc/x", "it timed out"), id="a-path-as-the-code"),
    pytest.param(("timed out", "it timed out"), id="a-code-with-a-space"),
]


def _planted_in(pair, *, home: str):
    """A scan whose only ERROR scanner carries *pair* in its row or in a report."""
    model = AshAggregatedResults(ash_config=get_default_config())
    code, sentence = pair
    if home == "row":
        model.scanner_results["example-tool"] = ScannerTargetStatusInfo(
            status=ScannerStatus.ERROR,
            error_reason_code=code,
            error_reason=sentence,
        )
        model.additional_reports["example-tool"] = {
            "source": {"scanner_name": "example-tool", "status": "ERROR"}
        }
    else:
        model.scanner_results["example-tool"] = ScannerTargetStatusInfo(
            status=ScannerStatus.ERROR
        )
        model.additional_reports["example-tool"] = {
            "source": {
                "scanner_name": "example-tool",
                "status": "ERROR",
                "error_reason_code": code,
                "error_reason": sentence,
            }
        }
    model._flat_cache = None
    return model


def _carries(code, sentence, pair) -> bool:
    """Whether a reason built from *pair* shows in (code, sentence), whole or in part."""
    planted_code, planted_sentence = pair
    return (code, sentence) == pair or any(
        part and (part in (code or "") or part in (sentence or ""))
        for part in (planted_code.strip(), planted_sentence.strip())
        if len(part) > 8
    )


class TestAPairThatIsNotFitIsNoReason:
    @pytest.mark.parametrize("pair", UNFIT)
    @pytest.mark.parametrize("holder", ["a dict", "a row"])
    def test_the_reader_gives_none(self, pair, holder):
        code, sentence = pair
        value = (
            {"error_reason_code": code, "error_reason": sentence}
            if holder == "a dict"
            else ScannerTargetStatusInfo(
                status=ScannerStatus.ERROR,
                error_reason_code=code,
                error_reason=sentence,
            )
        )

        assert unified_metrics._reason_pair(value) is None

    @pytest.mark.parametrize("holder", ["a dict", "a row"])
    def test_control_a_fit_pair_is_read(self, holder):
        code, sentence = FIT
        value = (
            {"error_reason_code": code, "error_reason": sentence}
            if holder == "a dict"
            else ScannerTargetStatusInfo(
                status=ScannerStatus.ERROR,
                error_reason_code=code,
                error_reason=sentence,
            )
        )

        assert unified_metrics._reason_pair(value) == FIT

    @pytest.mark.parametrize("home", ["row", "report"])
    @pytest.mark.parametrize("pair", UNFIT)
    def test_nothing_is_recorded_for_the_scanner(self, pair, home):
        model = _planted_in(pair, home=home)

        assert recorded_error_reason(model, "example-tool") is None


class TestItNeverReachesWhatCopiesIt:
    """Where a reason is copied: the metrics, the rebuilt row, the rows ash.flat.json
    and the YAML report are written from, and the reports for people."""

    @pytest.mark.parametrize("home", ["row", "report"])
    @pytest.mark.parametrize("pair", UNFIT)
    def test_the_metrics_do_not_carry_it(self, pair, home):
        (metrics,) = [
            found
            for found in get_unified_scanner_metrics(_planted_in(pair, home=home))
            if found.scanner_name == "example-tool"
        ]

        assert not _carries(metrics.error_reason_code, metrics.error_reason, pair)

    @pytest.mark.parametrize("home", ["row", "report"])
    @pytest.mark.parametrize("pair", UNFIT)
    def test_the_rebuilt_row_does_not_carry_it(self, pair, home):
        rebuilt = populate_metrics_from_unified_source(_planted_in(pair, home=home))

        row = rebuilt.scanner_results["example-tool"]

        assert not _carries(row.error_reason_code, row.error_reason, pair)

    @pytest.mark.parametrize("home", ["row", "report"])
    @pytest.mark.parametrize("pair", UNFIT)
    def test_the_flat_rows_do_not_carry_it(self, pair, home):
        (row,) = ReportContentEmitter(
            _planted_in(pair, home=home)
        ).get_scanner_results()

        assert not _carries(row["error_reason_code"], row["error_reason"], pair)

    @pytest.mark.parametrize("pair", UNFIT)
    def test_the_flat_rows_are_checked_again_whatever_the_metrics_hold(
        self, pair, monkeypatch
    ):
        """A second layer: the emitter drops a pair that fails even when the metrics
        it was handed hold one (a row built any other way)."""
        model = _planted_in(FIT, home="row")
        emitter = ReportContentEmitter(model)
        for metrics in emitter.scanner_metrics:
            metrics.error_reason_code, metrics.error_reason = pair

        (row,) = emitter.get_scanner_results()

        assert (row["error_reason_code"], row["error_reason"]) == (None, None)

    @pytest.mark.parametrize("pair", UNFIT)
    def test_a_half_checked_pair_is_dropped_whole(self, pair):
        """A fit sentence under an unfit code is not shown under a code it was not
        recorded with, and the other way round."""
        model = _planted_in(FIT, home="row")
        emitter = ReportContentEmitter(model)
        for metrics in emitter.scanner_metrics:
            metrics.error_reason_code = pair[0]

        (row,) = emitter.get_scanner_results()

        assert row["error_reason"] != FIT[1] or row["error_reason_code"] == FIT[0]


class TestControlAFitPairIsCarriedThrough:
    @pytest.mark.parametrize("home", ["row", "report"])
    def test_every_place_carries_it(self, home):
        model = _planted_in(FIT, home=home)

        assert recorded_error_reason(model, "example-tool") == FIT
        (metrics,) = [
            found
            for found in get_unified_scanner_metrics(model)
            if found.scanner_name == "example-tool"
        ]
        assert (metrics.error_reason_code, metrics.error_reason) == FIT
        row = populate_metrics_from_unified_source(model).scanner_results[
            "example-tool"
        ]
        assert (row.error_reason_code, row.error_reason) == FIT
        (flat,) = ReportContentEmitter(model).get_scanner_results()
        assert (flat["error_reason_code"], flat["error_reason"]) == FIT
