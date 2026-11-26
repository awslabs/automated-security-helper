# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The human reports fold duplicate clusters when asked, and only then.

A real model with two scanners' SARIF runs reporting one CVE in one package (and
one finding only grype reports) is rendered as HTML, Markdown and text. Default
off leaves every report as it has always been; on shows the pair as one row with
a note naming the other scanner, and gives deduplicated counts beside, never in
place of, the per-scanner counts. The machine-readable exports, the ids, the
per-scanner metrics and the exit-code inputs are the same either way.
"""

import csv
import inspect
import json
from io import StringIO

import pytest
from typer.testing import CliRunner

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.cli.main import app
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.unified_metrics import get_unified_scanner_metrics
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.csv_reporter import (
    CsvReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
    FlatJSONReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
    MarkdownReporterConfig,
    MarkdownReporterConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
    TextReporterConfig,
    TextReporterConfigOptions,
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

pytestmark = pytest.mark.unit

CVE = "CVE-2024-0001"
NOTE = f"Also reported by trivy {CVE} (MEDIUM)"


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


def _model(*, fold=False, annotate=False) -> AshAggregatedResults:
    left_pad = {
        "package_name": "left-pad",
        "package_path": "node_modules/left-pad",
    }
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.ash_config.global_settings.deduplication.fold = fold
    model.ash_config.global_settings.deduplication.annotate = annotate
    model.sarif = SarifReport(
        runs=[
            _run("grype", CVE, "error", package_version="1.0.0", **left_pad),
            _run("trivy", CVE, "warning", package_version="1.0.1", **left_pad),
            _run(
                "grype",
                "CVE-2024-0002",
                "note",
                package_name="other",
                package_path="node_modules/other",
            ),
        ]
    )
    return model


@pytest.fixture
def context(tmp_path) -> PluginContext:
    return PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        config=get_default_config(),
    )


def _markdown(context, model):
    config = MarkdownReporterConfig(
        options=MarkdownReporterConfigOptions(
            include_findings_table=True, include_detailed_findings=True
        )
    )
    return MarkdownReporter(config=config, context=context).report(model)


def _text(context, model):
    config = TextReporterConfig(
        options=TextReporterConfigOptions(
            include_findings_table=True, include_detailed_findings=True
        )
    )
    return TextReporter(config=config, context=context).report(model)


def _overview_rows(markdown):
    lines = markdown.splitlines()
    start = next(i for i, line in enumerate(lines) if line == "## Findings overview")
    table = []
    for line in lines[start + 2 :]:
        if not line.startswith("|"):
            if table:
                break
            continue
        table.append(line)
    return table


class TestOffIsTheReportItHasAlwaysBeen:
    def test_markdown_lists_every_finding_and_no_duplicates_column(self, context):
        markdown = _markdown(context, _model())
        header, _divider, *rows = _overview_rows(markdown)
        assert header == "| Severity | Scanner | Rule ID | Title | File |"
        assert len(rows) == 3
        assert "Also reported by" not in markdown
        assert "Deduplicated" not in markdown

    def test_text_lists_every_finding_and_no_note(self, context):
        text = _text(context, _model())
        assert "Also reported by" not in text
        assert "Deduplicated" not in text

    def test_html_has_a_card_per_finding_and_no_notice(self, context):
        html = HtmlReporter(context=context).report(_model())
        assert html.count('class="finding-card"') == 3
        assert "Duplicates folded" not in html
        assert "<strong>Duplicates:</strong>" not in html

    def test_annotate_alone_does_not_fold(self, context):
        markdown = _markdown(context, _model(annotate=True))
        _header, _divider, *rows = _overview_rows(markdown)
        assert len(rows) == 3

    def test_the_summary_has_no_deduplicated_key(self):
        emitter = ReportContentEmitter(_model(), human_presentation=True)
        assert "deduplicated" not in emitter.get_scan_summary()

    def test_the_rows_carry_no_note_key(self):
        emitter = ReportContentEmitter(_model(), human_presentation=True)
        assert all("duplicate_note" not in r for r in emitter.get_findings_overview())
        assert all("duplicate_note" not in r for r in emitter.get_detailed_findings())


class TestOnShowsOneRowPerCluster:
    def test_markdown_overview_has_one_row_for_the_pair_and_a_note(self, context):
        markdown = _markdown(context, _model(fold=True))
        header, _divider, *rows = _overview_rows(markdown)
        assert header.endswith("| Duplicates |")
        assert len(rows) == 2
        (pair,) = [row for row in rows if "trivy" in row]
        assert "| grype |" in pair, "the HIGH grype row stands for the cluster"
        assert NOTE in pair
        lone = next(row for row in rows if "CVE-2024-0002" in row)
        assert lone.rstrip().endswith("|  |")

    def test_markdown_detailed_findings_name_the_duplicates_once(self, context):
        markdown = _markdown(context, _model(fold=True))
        assert markdown.count(f"- Duplicates: {NOTE}") == 1
        # One exact note, not an or of two phrasings (the second was a
        # substring of every Showing line, so the assertion could not fail).
        assert "Showing 1 of 1 actionable findings, highest severity first." in markdown

    def test_the_showing_note_counts_the_rows_the_list_can_show(self, context):
        emitter = ReportContentEmitter(_model(fold=True), human_presentation=True)
        listed = emitter.get_detailed_findings(100)
        assert emitter.actionable_finding_count() == len(listed)
        off = ReportContentEmitter(_model(), human_presentation=True)
        assert off.actionable_finding_count() == len(off.get_detailed_findings(100))
        assert off.actionable_finding_count() == len(listed) + 1

    def test_the_markdown_outcome_gives_counts_beside_the_scanner_counts(self, context):
        off = _markdown(context, _model())
        on = _markdown(context, _model(fold=True))
        assert "Deduplicated: " in on
        assert "1 live duplicate row folded" in on
        assert "The per-scanner counts are unchanged." in on
        # The line the scanners' own counts are in is the same either way.
        count_line = next(line for line in off.splitlines() if "actionable** ·" in line)
        assert count_line in on.splitlines()

    def test_text_names_the_duplicates_under_the_row_and_in_the_detail(self, context):
        text = _text(context, _model(fold=True))
        assert f"Duplicates: {NOTE}" in text
        assert f"  {NOTE}" in text
        assert "Deduplicated: " in text

    def test_html_has_one_card_for_the_pair_with_the_note_and_a_notice(self, context):
        html = HtmlReporter(context=context).report(_model(fold=True))
        assert html.count('class="finding-card"') == 2
        assert "<h3>Duplicates folded</h3>" in html
        assert f"<strong>Duplicates:</strong> {NOTE}" in html
        assert "2 findings in this report" in html

    def test_top_hotspots_count_a_cluster_once(self):
        # The pair shares a file here, so the folded count must differ from the
        # unfolded one: the earlier form of this test used the shared model,
        # whose pair carries no file, and so passed whatever the fold did.
        from automated_security_helper.schemas.sarif_schema_model import Location

        where = Location.model_validate(
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py"},
                    "region": {"startLine": 1},
                }
            }
        )

        def model(fold):
            left_pad = {
                "package_name": "left-pad",
                "package_path": "node_modules/left-pad",
            }
            built = AshAggregatedResults()
            built.ash_config = get_default_config()
            built.ash_config.global_settings.deduplication.fold = fold
            runs = [
                _run("grype", CVE, "error", package_version="1.0.0", **left_pad),
                _run("trivy", CVE, "warning", package_version="1.0.1", **left_pad),
            ]
            for run in runs:
                run.results[0].locations = [where]
            built.sarif = SarifReport(runs=runs)
            return built

        def hotspots(fold):
            emitter = ReportContentEmitter(model(fold), human_presentation=True)
            return emitter.get_top_hotspots(10)

        (off,) = hotspots(False)
        (on,) = hotspots(True)
        assert off["location"] == on["location"]
        assert off["count"] == 2
        assert on["count"] == 1

    def test_the_fold_counts_sit_beside_the_scanner_counts(self):
        off = ReportContentEmitter(_model(), human_presentation=True)
        on = ReportContentEmitter(_model(fold=True), human_presentation=True)
        off_summary, on_summary = off.get_scan_summary(), on.get_scan_summary()
        folded = on_summary["deduplicated"]
        assert folded["folded_rows"] == 1
        assert folded["active"] == 2
        assert folded["actionable"] == off_summary["actionable"] - 1
        # No per-severity breakdown: no reporter rendered the one this carried.
        assert set(folded) == {"active", "actionable", "folded_rows"}
        for key in ("actionable", "active", "counts", "suppressed", "below_threshold"):
            assert on_summary[key] == off_summary[key], key
        assert on.get_scanner_results() == off.get_scanner_results()


def _split_gate_model(*, trivy_threshold="LOW") -> AshAggregatedResults:
    """One cluster whose severer member is below ITS scanner's gate.

    grype reports the pair's MEDIUM row under a HIGH threshold (below it);
    trivy reports its LOW row under *trivy_threshold* (actionable at "LOW").
    """
    left_pad = {
        "package_name": "left-pad",
        "package_path": "node_modules/left-pad",
    }
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.ash_config.global_settings.deduplication.fold = True
    model.ash_config.scanners.grype.options.severity_threshold = "HIGH"
    model.ash_config.scanners.trivy.options.severity_threshold = trivy_threshold
    model.sarif = SarifReport(
        runs=[
            _run("grype", CVE, "warning", package_version="1.0.0", **left_pad),
            _run("trivy", CVE, "note", package_version="1.0.1", **left_pad),
        ]
    )
    return model


class TestTheRepresentativeIsActionableFirst:
    def test_an_actionable_finding_is_never_hidden_under_a_below_threshold_card(self):
        # The gate is per scanner, so a cluster can hold a row one scanner's
        # threshold leaves below it beside a less severe row another scanner's
        # gate makes actionable. Severity ranking alone made the
        # below-threshold row the card for both, which the HTML's default view
        # hides, while the masthead still counted one actionable finding.
        emitter = ReportContentEmitter(_split_gate_model(), human_presentation=True)
        shown, notes = emitter.fold_findings(emitter.flat_vulns)
        (representative,) = shown
        assert representative.scanner == "trivy"
        assert emitter.is_finding_actionable(representative)
        assert "grype" in notes[id(representative)]
        # The actionable list and its count agree with the card.
        detailed = emitter.get_detailed_findings(100)
        assert emitter.actionable_finding_count() == len(detailed) == 1
        assert detailed[0]["scanner"] == "trivy"

    def test_with_no_actionable_member_the_severity_ranked_primary_stands(self):
        emitter = ReportContentEmitter(
            _split_gate_model(trivy_threshold="HIGH"), human_presentation=True
        )
        shown, _notes = emitter.fold_findings(emitter.flat_vulns)
        (representative,) = shown
        assert representative.scanner == "grype"

    def test_fold_findings_refuses_a_row_that_is_not_the_models(self):
        emitter = ReportContentEmitter(_model(fold=True), human_presentation=True)
        foreign = _model().to_flat_vulnerabilities()[:1]
        with pytest.raises(ValueError, match="emitter's own rows"):
            emitter.fold_findings(foreign)


class TestTheSummaryLineSaysSomethingOrNothing:
    def test_the_line_is_silent_when_the_fold_folded_nothing(self):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
            deduplicated_summary_text,
        )

        model = _model(fold=True)
        # Only the lone finding: the fold is armed and folds nothing.
        model.sarif = SarifReport(
            runs=[
                _run(
                    "grype",
                    "CVE-2024-0002",
                    "note",
                    package_name="other",
                    package_path="node_modules/other",
                )
            ]
        )
        emitter = ReportContentEmitter(model, human_presentation=True)
        summary = emitter.get_scan_summary()
        assert summary["deduplicated"]["folded_rows"] == 0
        assert deduplicated_summary_text(summary) is None
        assert deduplicated_summary_text({}) is None

    def test_the_line_says_it_counts_live_rows(self):
        from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
            deduplicated_summary_text,
        )

        emitter = ReportContentEmitter(_model(fold=True), human_presentation=True)
        line = deduplicated_summary_text(emitter.get_scan_summary())
        assert line is not None
        assert "1 live duplicate row folded" in line
        assert "suppressed duplicates fold apart" in line
        assert "The per-scanner counts are unchanged." in line


class TestWhatTheFoldNeverTouches:
    def test_the_machine_readable_reports_are_the_same_with_fold_on(
        self, test_plugin_context
    ):
        off, on = _model(), _model(fold=True)
        assert CsvReporter(context=test_plugin_context).report(on) == CsvReporter(
            context=test_plugin_context
        ).report(off)
        flat_off = json.loads(FlatJSONReporter(context=test_plugin_context).report(off))
        flat_on = json.loads(FlatJSONReporter(context=test_plugin_context).report(on))
        for key in ("findings", "scanner_metrics", "top_hotspots"):
            assert flat_on[key] == flat_off[key]

    def test_the_emitter_never_folds_for_a_machine_reader(self):
        emitter = ReportContentEmitter(_model(fold=True))
        assert emitter.fold is False
        assert len(emitter.get_findings_overview()) == 3
        assert "deduplicated" not in emitter.get_scan_summary()

    def test_finding_ids_are_the_scanner_inclusive_identity(self):
        off = [v.id for v in _model().to_flat_vulnerabilities()]
        on = [v.id for v in _model(fold=True).to_flat_vulnerabilities()]
        assert on == off
        assert len(set(on)) == len(on)

    def test_per_scanner_metrics_are_blind_to_the_fold(self):
        assert get_unified_scanner_metrics(_model(fold=True)) == (
            get_unified_scanner_metrics(_model())
        )

    def test_the_fold_changes_no_flat_row(self):
        model = _model(fold=True)
        before = [v.model_dump() for v in model.to_flat_vulnerabilities()]
        ReportContentEmitter(model, human_presentation=True).get_detailed_findings()
        assert [v.model_dump() for v in model.to_flat_vulnerabilities()] == before

    def test_the_csv_with_both_flags_keeps_every_row(self, test_plugin_context):
        text = CsvReporter(context=test_plugin_context).report(
            _model(fold=True, annotate=True)
        )
        assert len(list(csv.DictReader(StringIO(text)))) == 3


def _write(output_dir, model):
    (output_dir / "ash_aggregated_results.json").write_text(
        model.model_dump_json(by_alias=True), encoding="utf-8"
    )


def _cli_markdown(output_dir, *extra):
    result = CliRunner().invoke(
        app,
        [
            "report",
            "--format",
            "markdown",
            "--output-dir",
            str(output_dir),
            "--log-level",
            "ERROR",
            *extra,
        ],
    )
    assert result.exit_code == 0, result.output
    return result.stdout


def test_ash_report_flag_turns_the_fold_on(tmp_path):
    _write(tmp_path, _model())
    assert "Also reported by" not in _cli_markdown(tmp_path)
    assert NOTE in _cli_markdown(tmp_path, "--fold-duplicates")


def test_ash_report_honors_the_recorded_setting_and_the_override(tmp_path):
    _write(tmp_path, _model(fold=True))
    assert NOTE in _cli_markdown(tmp_path)
    _write(tmp_path, _model())
    folded = _cli_markdown(
        tmp_path, "--config-overrides", "global_settings.deduplication.fold=true"
    )
    assert NOTE in folded


def test_scan_and_report_declare_the_flag_off_by_default():
    from automated_security_helper.cli.report import report_command
    from automated_security_helper.cli.scan import run_ash_scan_cli_command

    for command in (run_ash_scan_cli_command, report_command):
        parameter = inspect.signature(command).parameters["fold_duplicates"]
        assert parameter.default is False
        # typer reads a leading string as the option's name.
        assert parameter.annotation.__metadata__[0].default == "--fold-duplicates"
