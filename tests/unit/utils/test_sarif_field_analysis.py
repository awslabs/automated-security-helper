"""Tests for utils/sarif_field_analysis.py — verify move from cli/inspect."""

import warnings


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
                        if isinstance(arg, ast.Constant) and "deprecated" in str(arg.value).lower():
                            found = True
        assert found, "shim must call warnings.warn with 'deprecated'"


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
        import click

        with patch(
            "automated_security_helper.utils.sarif_field_analysis.generate_html_report"
        ):
            try:
                result = analyze_sarif_fields(
                    sarif_dir=str(sarif_dir),
                    output_dir=str(output_dir),
                )
            except click.exceptions.Exit:
                # Exit(1) means unexpected-missing-fields — that's fine for this test;
                # we just verify the output files were written correctly.
                result = None

        # Verify output was produced (JSON file contains the expected fields)
        import json as _json

        fields_json = output_dir / "sarif_fields.json"
        assert fields_json.exists()
        data = _json.loads(fields_json.read_text())
        assert isinstance(data, dict)
        assert any("ruleId" in key for key in data)
