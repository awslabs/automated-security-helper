# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An archive refused for an extraction limit reaches the exit code and the reports.

The archive converter refuses an archive over one of its extraction limits whole,
so none of its contents reach a scanner, and records the refusal with the limit's
name (``RefusedInputInfo.limit``). ``incomplete_converters`` counts such a record
the way it counts a converter that crashed, so under ``fail_on_incomplete_scanners``
(the default) the scan exits 1. A refusal without a limit (a symlinked input, a link
or ``..`` member, a nested archive) is reported and does not move the exit code.

Every refused input also reaches the console summary, the text and markdown
summaries, the flat JSON report and ``ash.sarif``; before, they were in ``ash.log``
and the results file only.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from rich.console import Console

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.metrics_table import print_converter_refusals
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _compute_exit_code,
    incomplete_converters,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
    RefusedInputInfo,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
    FlatJSONReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
    SarifReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
)
from automated_security_helper.utils.converter_refusals import (
    REFUSED_INPUT_NOTIFICATION_ID,
    SHOWN_IN_SUMMARY,
    converter_refusals,
    refusal_invocations,
)

pytestmark = pytest.mark.unit

_MODULE = "automated_security_helper.interactions.run_ash_scan"

OVER_LIMIT = RefusedInputInfo(
    path="vendor/declared.zip",
    reason="its member 'big.py' declares 2 bytes, outside the max_member_bytes "
    "extraction limit of 1",
    limit="max_member_bytes",
)
NESTED = RefusedInputInfo(
    path="dist/outer.zip",
    member="inner.zip",
    reason="it is named as an archive (.zip, .tar or .gz), and an archive inside "
    "an archive is not extracted, so its contents are not scanned",
)
SYMLINK = RefusedInputInfo(path="link.zip", reason="it is a symbolic link")


def _model(*refused: RefusedInputInfo) -> AshAggregatedResults:
    model = AshAggregatedResults(ash_config=get_default_config())
    model.converter_results["archive"] = ConverterStatusInfo(
        converted_paths=[], refused_inputs=list(refused)
    )
    return model


def _exit_code(tmp_path: Path, model: AshAggregatedResults, **opt_kwargs) -> int:
    opts = ScanOptions(
        source_dir=tmp_path / "src", output_dir=tmp_path / "out", **opt_kwargs
    )
    with patch(f"{_MODULE}.get_unified_scanner_metrics", return_value=[]):
        return _compute_exit_code(model, opts)


def _context() -> PluginContext:
    return PluginContext(
        source_dir=Path("."), output_dir=Path("."), config=get_default_config()
    )


class TestTheGate:
    def test_an_archive_over_a_limit_is_incomplete_conversion(self):
        listed = incomplete_converters(_model(OVER_LIMIT, NESTED))

        assert [row.name for row in listed] == ["archive"]
        assert "vendor/declared.zip (max_member_bytes)" in listed[0][1]

    def test_member_and_input_refusals_alone_are_not_incomplete_conversion(self):
        assert incomplete_converters(_model(NESTED, SYMLINK)) == []

    def test_an_archive_over_a_limit_exits_one_by_default(self, tmp_path):
        assert _exit_code(tmp_path, _model(OVER_LIMIT)) == 1

    def test_the_completeness_gate_turned_off_lets_it_through(self, tmp_path):
        model = _model(OVER_LIMIT)

        assert _exit_code(tmp_path, model, fail_on_incomplete_scanners=False) == 0

    def test_a_nested_archive_does_not_move_the_exit_code(self, tmp_path):
        assert _exit_code(tmp_path, _model(NESTED, SYMLINK)) == 0

    def test_an_older_results_row_without_limit_is_read_as_no_limit(self):
        row = ConverterStatusInfo.model_validate(
            {
                "converted_paths": [],
                "refused_inputs": [
                    {"path": "a.zip", "reason": "it is a symbolic link"}
                ],
            }
        )
        model = AshAggregatedResults(ash_config=get_default_config())
        model.converter_results["archive"] = row

        assert incomplete_converters(model) == []
        assert row.refused_inputs[0].model_dump() == {
            "path": "a.zip",
            "member": None,
            "reason": "it is a symbolic link",
        }


class TestTheReports:
    def test_refusals_leaving_the_scan_incomplete_are_listed_first(self):
        refusals = converter_refusals(_model(NESTED, SYMLINK, OVER_LIMIT))

        assert [r.path for r in refusals] == [
            "vendor/declared.zip",
            "dist/outer.zip",
            "link.zip",
        ]
        assert [r.scan_incomplete for r in refusals] == [True, False, False]

    def test_flat_json_lists_every_refusal(self):
        data = json.loads(
            FlatJSONReporter(context=_context()).report(_model(OVER_LIMIT, NESTED))
        )

        assert data["converter_refusals"] == [
            {
                "converter": "archive",
                "path": "vendor/declared.zip",
                "member": None,
                "reason": OVER_LIMIT.reason,
                "limit": "max_member_bytes",
                "scan_incomplete": True,
                "unlisted_members": None,
                "accepted": False,
                "accepted_reason": None,
            },
            {
                "converter": "archive",
                "path": "dist/outer.zip",
                "member": "inner.zip",
                "reason": NESTED.reason,
                "limit": None,
                "scan_incomplete": False,
                "unlisted_members": None,
                "accepted": False,
                "accepted_reason": None,
            },
        ]

    def test_flat_json_carries_an_empty_list_when_nothing_was_refused(self):
        data = json.loads(FlatJSONReporter(context=_context()).report(_model()))

        assert data["converter_refusals"] == []

    def test_sarif_carries_one_notification_per_refusal(self):
        model = _model(OVER_LIMIT, NESTED)
        before = model.sarif.model_dump_json()

        doc = json.loads(SarifReporter(context=_context()).report(model))

        notes = [
            note
            for run in doc["runs"]
            for invocation in run.get("invocations") or []
            for note in invocation.get("toolExecutionNotifications") or []
        ]
        assert [
            (
                note["level"],
                note["descriptor"]["id"],
                note["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            )
            for note in notes
        ] == [
            ("error", REFUSED_INPUT_NOTIFICATION_ID, "vendor/declared.zip"),
            ("warning", REFUSED_INPUT_NOTIFICATION_ID, "dist/outer.zip"),
        ]
        assert "member 'inner.zip' of 'dist/outer.zip'" in notes[1]["message"]["text"]
        assert model.sarif.model_dump_json() == before, (
            "the scan's own SARIF, which the exit-code gates read, was changed"
        )

    def test_sarif_is_unchanged_when_nothing_was_refused(self):
        model = _model()

        assert SarifReporter(context=_context()).report(model) == (
            model.sarif.model_dump_json(
                by_alias=True, exclude_none=True, exclude_unset=True
            )
        )

    def test_the_text_summary_names_each_refusal(self):
        report = TextReporter(context=_context()).report(_model(OVER_LIMIT, NESTED))

        lines = report.splitlines()
        assert "CONVERTER INPUTS NOT SCANNED" in lines
        assert (
            "- [scan incomplete] archive: 'vendor/declared.zip' was not scanned: "
            + OVER_LIMIT.reason
        ) in lines
        assert (
            "- archive: member 'inner.zip' of 'dist/outer.zip' was not scanned: "
            + NESTED.reason
        ) in lines

    def test_the_markdown_summary_names_each_refusal(self):
        report = MarkdownReporter(context=_context()).report(_model(OVER_LIMIT, NESTED))

        lines = report.splitlines()
        assert "### Converter inputs not scanned" in lines
        assert (
            "- **scan incomplete**: ` archive: 'vendor/declared.zip' was not scanned: "
            "its member 'big.py' declares 2 bytes, outside the max_member_bytes "
            "extraction limit of 1 `"
        ) in lines
        assert (
            "- ` archive: member 'inner.zip' of 'dist/outer.zip' was not scanned: "
            + NESTED.reason
            + " `"
        ) in lines

    def test_the_markdown_summary_renders_member_names_as_text(self):
        model = _model(
            RefusedInputInfo(
                path="a.zip",
                member="[docs](https://example.invalid)\n# heading.zip",
                reason="it is named as an archive",
            )
        )

        report = MarkdownReporter(context=_context()).report(model)

        line = next(line for line in report.splitlines() if "example.invalid" in line)
        assert line.startswith("- ` ") and line.endswith(" `"), line
        assert "[docs](https://example.invalid)\\x0a# heading.zip" in line
        assert "\n# heading" not in report

    def test_a_long_list_is_cut_short_with_a_count(self):
        many = [
            RefusedInputInfo(path="a.tar", member=f"m{i}.zip", reason="nested")
            for i in range(SHOWN_IN_SUMMARY + 5)
        ]

        report = TextReporter(context=_context()).report(_model(*many))

        assert report.count("member 'm") == SHOWN_IN_SUMMARY
        assert "and 5 more" in report

    def test_the_markdown_summary_cuts_a_long_list_short_with_a_count(self):
        """The summary posted to pull requests, not only the text one."""
        many = [
            RefusedInputInfo(path="a.tar", member=f"m{i}.zip", reason="nested")
            for i in range(SHOWN_IN_SUMMARY + 5)
        ]

        report = MarkdownReporter(context=_context()).report(_model(*many))

        assert report.count("member 'm") == SHOWN_IN_SUMMARY
        assert "- ... and 5 more" in report

    def test_the_console_cuts_a_long_list_short_with_a_count(self):
        many = [
            RefusedInputInfo(path="a.tar", member=f"m{i}.zip", reason="nested")
            for i in range(SHOWN_IN_SUMMARY + 5)
        ]
        console = Console(record=True, width=300, color_system=None)

        print_converter_refusals(_model(*many), console)

        text = console.export_text()
        assert text.count("member 'm") == SHOWN_IN_SUMMARY
        assert "Not scanned: 5 more converter input(s)" in text

    def test_a_sarif_invocation_is_unsuccessful_only_when_coverage_was_lost(self):
        (lost,) = refusal_invocations(_model(OVER_LIMIT, NESTED))
        (reported,) = refusal_invocations(_model(NESTED, SYMLINK))

        assert lost.executionSuccessful is False
        assert reported.executionSuccessful is True

    def test_the_console_summary_names_each_refusal(self):
        console = Console(record=True, width=300, color_system=None)

        print_converter_refusals(_model(OVER_LIMIT, NESTED), console)

        text = console.export_text()
        assert "Not scanned (scan incomplete): archive: 'vendor/declared.zip'" in text
        assert "Not scanned: archive: member 'inner.zip' of 'dist/outer.zip'" in text


class TestFailedInputsInTheReports:
    """An input a converter could not convert is listed with the refusals.

    It is recorded under ``failed_inputs`` rather than ``refused_inputs``, and it
    fails the completeness gate, so the reports mark it as leaving the scan
    incomplete, as they mark an archive over an extraction limit.
    """

    @staticmethod
    def _model():
        from automated_security_helper.models.asharp_model import FailedInputInfo

        model = AshAggregatedResults(ash_config=get_default_config())
        model.converter_results["archive"] = ConverterStatusInfo(
            converted_paths=[],
            refused_inputs=[NESTED],
            failed_inputs=[
                FailedInputInfo(path="dist/cut.tar", reason="ReadError: truncated")
            ],
        )
        return model

    def test_a_failed_input_is_listed_first_and_marked_incomplete(self):
        refusals = converter_refusals(self._model())

        assert [(r.path, r.member, r.scan_incomplete) for r in refusals] == [
            ("dist/cut.tar", None, True),
            ("dist/outer.zip", "inner.zip", False),
        ]
        assert refusals[0].message() == (
            "archive: 'dist/cut.tar' was not scanned: ReadError: truncated"
        )

    def test_the_flat_json_and_sarif_carry_the_failed_input(self):
        model = self._model()

        rows = json.loads(FlatJSONReporter(context=_context()).report(model))[
            "converter_refusals"
        ]
        doc = json.loads(SarifReporter(context=_context()).report(model))
        levels = {
            note["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]: note[
                "level"
            ]
            for run in doc["runs"]
            for invocation in run.get("invocations") or []
            for note in invocation.get("toolExecutionNotifications") or []
        }

        assert [(r["path"], r["scan_incomplete"]) for r in rows] == [
            ("dist/cut.tar", True),
            ("dist/outer.zip", False),
        ]
        assert levels == {"dist/cut.tar": "error", "dist/outer.zip": "warning"}

    def test_the_text_summary_names_the_failed_input(self):
        report = TextReporter(context=_context()).report(self._model())

        assert (
            "- [scan incomplete] archive: 'dist/cut.tar' was not scanned: "
            "ReadError: truncated"
        ) in report.splitlines()
