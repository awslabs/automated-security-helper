# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Duplicate annotation and fold are layers over the reports, and nothing else.

Two conformance rows the design names:

* metrics-blind: the unified per-scanner metrics, the SARIF-versus-statistics
  count check and the SARIF itself are identical with ``annotate`` and ``fold``
  off, on, and after every human and flat reporter has run;
* baseline-untouched: ``apply_baseline`` removes the same findings and records
  the same outcome whether the current scan asks for the annotation or not, and
  whether the reports ran before the baseline was applied or after it. A
  baseline that holds one scanner's copy of a duplicate pair never removes the
  other scanner's copy, because a cluster is not an identity.
"""

import copy

import pytest

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.scanner_statistics_calculator import (
    ScannerStatisticsCalculator,
)
from automated_security_helper.core.unified_metrics import get_unified_scanner_metrics
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerTargetStatusInfo,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
    CsvReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
    FlatJSONReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Message,
    Message1,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.scan_baseline import ScanBaseline, apply_baseline

pytestmark = pytest.mark.unit

CVE = "CVE-2024-0001"
LEFT_PAD = {"package_name": "left-pad", "package_path": "node_modules/left-pad"}
OTHER = {"package_name": "other", "package_path": "node_modules/other"}


def _run(scanner, rule_id, level, **package):
    props = PropertyBag(tags=[f"tool_name::{scanner}"])
    props.__pydantic_extra__ = {"scanner_name": scanner, **package}
    return Run(
        tool=Tool(driver=ToolComponent(name=scanner)),
        results=[
            Result(
                ruleId=rule_id,
                level=level,
                message=Message(root=Message1(text=f"{scanner} says {rule_id}")),
                properties=props,
            )
        ],
    )


def _model(*, on=False, runs=None) -> AshAggregatedResults:
    """grype and trivy report one CVE in one package; grype reports one more."""
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.ash_config.global_settings.deduplication.annotate = on
    model.ash_config.global_settings.deduplication.fold = on
    model.sarif = SarifReport(
        runs=runs
        if runs is not None
        else [
            _run("grype", CVE, "error", package_version="1.0.0", **LEFT_PAD),
            _run("trivy", CVE, "warning", package_version="1.0.1", **LEFT_PAD),
            _run("grype", "CVE-2024-0002", "note", **OTHER),
        ]
    )
    model.scanner_results = {
        name: ScannerTargetStatusInfo(status="PASSED") for name in ("grype", "trivy")
    }
    return model


def _baseline(model) -> ScanBaseline:
    return ScanBaseline("abc", model, tuple(model.to_flat_vulnerabilities()))


def _every_report(context, model):
    """Run every reporter the two switches touch, in the order a scan does."""
    CsvReporter(context=context).report(model)
    FlatJSONReporter(context=context).report(model)
    MarkdownReporter(context=context).report(model)
    TextReporter(context=context).report(model)


def _surviving(model):
    return [
        (run.tool.driver.name, result.ruleId.root)
        for run in model.sarif.runs
        for result in (run.results or [])
    ]


class TestMetricsBlind:
    def test_unified_metrics_are_the_same_off_and_on(self):
        assert get_unified_scanner_metrics(_model(on=True)) == (
            get_unified_scanner_metrics(_model())
        )

    def test_unified_metrics_are_the_same_after_every_reporter_ran(
        self, test_plugin_context
    ):
        model = _model(on=True)
        before = copy.deepcopy(get_unified_scanner_metrics(model))
        _every_report(test_plugin_context, model)
        assert get_unified_scanner_metrics(model) == before
        assert before == get_unified_scanner_metrics(_model())

    def test_the_sarif_is_not_changed_by_the_reporters(self, test_plugin_context):
        model = _model(on=True)
        before = model.sarif.model_dump_json(by_alias=True)
        _every_report(test_plugin_context, model)
        assert model.sarif.model_dump_json(by_alias=True) == before
        assert before == _model().sarif.model_dump_json(by_alias=True)

    def test_the_sarif_count_check_holds_with_the_switches_on(
        self, test_plugin_context
    ):
        off, on = _model(), _model(on=True)
        _every_report(test_plugin_context, on)
        assert ScannerStatisticsCalculator.verify_sarif_finding_counts(on) == (
            ScannerStatisticsCalculator.verify_sarif_finding_counts(off)
        )

    def test_finding_ids_are_the_same_off_and_on(self, test_plugin_context):
        off = [v.id for v in _model().to_flat_vulnerabilities()]
        on_model = _model(on=True)
        _every_report(test_plugin_context, on_model)
        assert [v.id for v in on_model.to_flat_vulnerabilities()] == off
        assert len(set(off)) == len(off) == 3


class TestBaselineUntouched:
    def _apply(self, current, baseline_model):
        outcome = apply_baseline(current, _baseline(baseline_model))
        return outcome, _surviving(current)

    def test_a_full_baseline_removes_the_same_findings_off_and_on(self):
        off_outcome, off_left = self._apply(_model(), _model())
        on_outcome, on_left = self._apply(_model(on=True), _model())
        assert on_outcome == off_outcome
        assert off_outcome.matched == 3
        assert on_left == off_left == []

    def test_the_reports_running_first_change_nothing(self, test_plugin_context):
        off_outcome, off_left = self._apply(_model(), _model())
        current = _model(on=True)
        _every_report(test_plugin_context, current)
        on_outcome, on_left = self._apply(current, _model())
        assert on_outcome == off_outcome
        assert on_left == off_left

    def test_the_reports_running_after_the_baseline_see_what_is_left(
        self, test_plugin_context
    ):
        # Only grype's rows are in the baseline; trivy's copy of the shared CVE
        # remains, alone, so it is in no cluster and is reported as itself.
        baseline = _model(
            runs=[
                _run("grype", CVE, "error", package_version="1.0.0", **LEFT_PAD),
                _run("grype", "CVE-2024-0002", "note", **OTHER),
            ]
        )
        current = _model(on=True)
        outcome = apply_baseline(current, _baseline(baseline))
        assert outcome.matched == 2
        assert _surviving(current) == [("trivy", CVE)]
        text = CsvReporter(context=test_plugin_context).report(current)
        assert "duplicate_of" in text.splitlines()[0]
        rows = text.splitlines()[1:]
        assert len(rows) == 1
        assert rows[0].count("trivy") >= 1

    def test_a_cluster_is_not_an_identity_for_the_baseline(self):
        # The baseline names the grype copy of the duplicate pair only. The
        # trivy copy has its own scanner-inclusive id and is not removed, with
        # the fold on or off.
        baseline_runs = [
            _run("grype", CVE, "error", package_version="1.0.0", **LEFT_PAD)
        ]
        results = {}
        for on in (False, True):
            current = _model(on=on)
            outcome = apply_baseline(current, _baseline(_model(runs=baseline_runs)))
            results[on] = (outcome.matched, _surviving(current))
        assert results[True] == results[False]
        matched, left = results[True]
        assert matched == 1
        assert ("trivy", CVE) in left
        assert ("grype", CVE) not in left

    def test_applying_a_baseline_does_not_turn_the_switches_on_or_off(self):
        current = _model()
        apply_baseline(current, _baseline(_model()))
        dedup = current.ash_config.global_settings.deduplication
        assert (dedup.annotate, dedup.fold) == (False, False)
        current = _model(on=True)
        apply_baseline(current, _baseline(_model()))
        dedup = current.ash_config.global_settings.deduplication
        assert (dedup.annotate, dedup.fold) == (True, True)
