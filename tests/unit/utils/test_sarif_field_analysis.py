"""Tests for utils/sarif_field_analysis.py — verify move from cli/inspect."""

import sys

import pytest


@pytest.mark.unit
class TestImportLocation:
    def test_import_from_utils(self):
        from automated_security_helper.utils.sarif_field_analysis import (
            analyze_sarif_fields,
        )

        assert callable(analyze_sarif_fields)

    def test_old_shim_re_exports_analyze_sarif_fields(self):
        # The shim must still expose analyze_sarif_fields so callers don't break.
        import automated_security_helper.cli.inspect.sarif_fields as shim

        assert callable(shim.analyze_sarif_fields)

    def test_old_shim_has_deprecation_warning_call(self):
        # Confirm the shim source contains a warnings.warn(DeprecationWarning) call
        # so we know backward-compat is explicitly signalled to users who import it.
        import ast
        from pathlib import Path

        shim_path = (
            Path(__file__).parent.parent.parent.parent
            / "automated_security_helper"
            / "cli"
            / "inspect"
            / "sarif_fields.py"
        )
        tree = ast.parse(shim_path.read_text())
        found = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr == "warn":
                    for arg in node.args:
                        if (
                            isinstance(arg, ast.Constant)
                            and "deprecated" in str(arg.value).lower()
                        ):
                            found = True
        assert found, "shim must call warnings.warn with 'deprecated'"


@pytest.mark.unit
class TestAnalyzeSarifFieldsLogic:
    def test_returns_field_set_from_minimal_sarif(self, tmp_path):
        import json
        from automated_security_helper.utils.sarif_field_analysis import (
            analyze_sarif_fields,
        )
        from unittest.mock import patch

        sarif_dir = tmp_path / "ash_output"
        reports_dir = sarif_dir / "reports"
        reports_dir.mkdir(parents=True)

        sarif_payload = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "TEST001",
                            "level": "error",
                            "message": {"text": "test finding"},
                        }
                    ]
                }
            ]
        }
        (reports_dir / "test.sarif").write_text(json.dumps(sarif_payload))

        output_dir = tmp_path / "out"

        # analyze_sarif_fields raises typer.Exit on unexpected missing fields;
        # patch generate_html_report to avoid filesystem side-effects in HTML gen.
        #
        # Catch typer.Exit rather than click.exceptions.Exit. Those named the same
        # class until typer 0.27, which vendored click as typer._click -- typer.Exit
        # is now typer._click.exceptions.Exit and is not a subclass of the
        # standalone click's Exit, so catching click's let the exception escape.
        # typer.Exit is the public API and is correct on either side of that change.
        import typer

        with patch(
            "automated_security_helper.utils.sarif_field_analysis.generate_html_report"
        ):
            try:
                analyze_sarif_fields(
                    sarif_dir=str(sarif_dir),
                    output_dir=str(output_dir),
                )
            except typer.Exit:
                # Exit(1) means unexpected-missing-fields — that's fine for this test;
                # we just verify the output files were written correctly.
                pass

        # Verify output was produced (JSON file contains the expected fields)
        import json as _json

        fields_json = output_dir / "sarif_fields.json"
        assert fields_json.exists()
        data = _json.loads(fields_json.read_text())
        assert isinstance(data, dict)
        assert any("ruleId" in key for key in data)


@pytest.mark.unit
class TestInAggregatePercentage:
    """`% in Aggregate` is the share of a scanner's included fields in the aggregate.

    It used to subtract the scanner's intentionally excluded fields as well. Those
    are never counted in the scanner's total (a path is either included or
    excluded), so the result could fall below zero: 9 included fields, none
    aggregated, and 1 excluded field printed -11.1%.
    """

    # Ten field paths that survive should_include_field (nine fields, of which
    # ``message`` is both itself and ``message.text``), plus ruleIndex, which is
    # intentionally excluded from the comparison.
    SCANNER_RESULT = {
        "ruleId": "B1",
        "ruleIndex": 0,
        "level": "error",
        "message": {"text": "m"},
        "kind": "fail",
        "rank": 1.0,
        "baselineState": "new",
        "hostedViewerUri": "x",
        "guid": "g",
        "correlationGuid": "c",
    }

    def _percentage(self, tmp_path, monkeypatch, capsys, aggregate_result):
        import json
        import re

        import typer

        from automated_security_helper.utils.sarif_field_analysis import (
            analyze_sarif_fields,
        )

        monkeypatch.setenv("COLUMNS", "250")
        sarif_dir = tmp_path / "ash_output"
        (sarif_dir / "scanners" / "bandit").mkdir(parents=True)
        (sarif_dir / "reports").mkdir(parents=True)
        (sarif_dir / "scanners" / "bandit" / "bandit.sarif").write_text(
            json.dumps({"runs": [{"results": [self.SCANNER_RESULT]}]})
        )
        (sarif_dir / "reports" / "ash.sarif").write_text(
            json.dumps({"runs": [{"results": [aggregate_result]}]})
        )

        try:
            analyze_sarif_fields(
                sarif_dir=str(sarif_dir), output_dir=str(tmp_path / "out")
            )
        except typer.Exit:
            pass  # exit 1 only signals unexpectedly missing fields

        out = re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().out)
        rows = [ln for ln in out.splitlines() if re.match(r"^│\s*bandit\s*│", ln)]
        assert len(rows) == 1, out
        cells = [c.strip() for c in rows[0].strip("│").split("│")]
        # Scanner, Total, Unique, Missing (Unexpected), Missing (Intentional), %
        return cells

    def test_nothing_aggregated_is_zero_not_negative(
        self, tmp_path, monkeypatch, capsys
    ):
        cells = self._percentage(tmp_path, monkeypatch, capsys, {"foo": "bar"})
        assert cells[1:] == ["10", "10", "10", "1", "0.0%"]

    def test_everything_aggregated_is_one_hundred(self, tmp_path, monkeypatch, capsys):
        aggregate = {k: v for k, v in self.SCANNER_RESULT.items() if k != "ruleIndex"}
        cells = self._percentage(tmp_path, monkeypatch, capsys, aggregate)
        # Unique Fields counts the scanners that emit a field; the aggregate
        # carries every field this scanner emits, so it is not one of them.
        assert cells[1:] == ["10", "10", "0", "1", "100.0%"]

    def test_partial_aggregation_counts_only_included_fields(
        self, tmp_path, monkeypatch, capsys
    ):
        cells = self._percentage(tmp_path, monkeypatch, capsys, {"ruleId": "B1"})
        assert cells[1:] == ["10", "10", "9", "1", "10.0%"]


@pytest.mark.unit
class TestHtmlReportWithNoFindings:
    def test_matched_share_with_zero_findings_does_not_divide_by_zero(self, tmp_path):
        from automated_security_helper.utils.meta_analysis.reporting import (
            generate_html_report,
        )

        validation_results = {
            "summary": {
                "total_findings": 0,
                "matched_findings": 0,
                "critical_missing_fields": 0,
                "important_missing_fields": 0,
                "informational_missing_fields": 0,
            },
            "match_statistics": {},
            "missing_fields": {},
        }
        out = tmp_path / "report.html"
        generate_html_report(validation_results, str(out), {})
        assert "Matched Findings: 0 (0.00%)" in out.read_text(encoding="utf-8")


@pytest.mark.integration
class TestTheCsvFilesUnderAnAsciiLocale:
    """The CSV files are UTF-8 whatever the locale, as the JSON files are."""

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="an ASCII locale cannot be chosen on Windows: open() takes its "
        "encoding from the ANSI code page (cp1252 here), whatever LC_ALL says",
    )
    def test_a_non_ascii_field_name_is_written(self, tmp_path):
        import json
        import os
        import subprocess
        import sys

        # The second character is outside Windows' ANSI code page (cp1252), which
        # is the locale encoding there and holds the first, so a file opened with
        # no encoding fails on every platform.
        field = "café字"
        sarif_dir = tmp_path / "ash_output"
        (sarif_dir / "reports").mkdir(parents=True)
        (sarif_dir / "reports" / "ash.sarif").write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {"driver": {"name": "example-tool"}},
                            "results": [
                                {
                                    "ruleId": "R1",
                                    "message": {"text": "x", field: "1"},
                                }
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        output_dir = tmp_path / "inspect"
        # The C locale with coercion and UTF-8 mode off: the locale's encoding is
        # ASCII, which open() with no encoding uses. The console streams stay UTF-8
        # (PYTHONIOENCODING), so only the files are under test.
        env = {
            **os.environ,
            "LC_ALL": "C",
            "LANG": "C",
            "PYTHONUTF8": "0",
            "PYTHONCOERCECLOCALE": "0",
            "PYTHONIOENCODING": "utf-8",
        }
        probe = (
            "import locale, sys\n"
            "print(locale.getpreferredencoding(False), file=sys.stderr)\n"
            "from automated_security_helper.utils.sarif_field_analysis import "
            "analyze_sarif_fields\n"
            f"analyze_sarif_fields(sarif_dir={str(sarif_dir)!r}, "
            f"output_dir={str(output_dir)!r})\n"
        )

        ran = subprocess.run(
            [sys.executable, "-c", probe],
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )

        # Windows has no ASCII locale to select; its locale encoding is the ANSI
        # code page, a "cpNNNN" name, which is not UTF-8 either.
        locale_name = ran.stderr.strip().lower()
        not_utf8 = (
            locale_name.startswith("cp")
            if sys.platform == "win32"
            else "ANSI_X3.4-1968" in ran.stderr or "ascii" in locale_name
        )
        assert not_utf8, (
            f"the probe did not run under a non-UTF-8 locale: {ran.stderr[:200]}"
        )
        assert ran.returncode == 0, ran.stderr[-2000:]
        csv_text = (output_dir / "sarif_fields.csv").read_text(encoding="utf-8")
        assert field in csv_text
