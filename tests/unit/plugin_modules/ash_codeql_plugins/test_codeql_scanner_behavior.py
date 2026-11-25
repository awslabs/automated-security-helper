# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CodeqlScanner: license gate, argv, severity mapping and failure handling.

The SARIF below is written by hand in the shape the CodeQL CLI documents (rules
with ``security-severity`` / ``problem.severity`` properties, results with
``ruleId``). It is NOT a capture from a real CodeQL run. scan() tests replace the
subprocess with a fake, so they run on every platform without the CodeQL CLI.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_codeql_plugins
from automated_security_helper.plugin_modules.ash_codeql_plugins import (
    codeql_scanner as cs,
)
from automated_security_helper.plugin_modules.ash_codeql_plugins.codeql_scanner import (
    CodeqlScanner,
    CodeqlScannerConfig,
    CodeqlScannerConfigOptions,
    canonical_language,
    rate_codeql_sarif,
    severity_for,
)
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit


def _rule(rule_id: str, **properties: Any) -> Dict[str, Any]:
    return {"id": rule_id, "properties": properties}


def _result(rule_id: str, uri: str, line: int, level: Optional[str] = "warning"):
    result: Dict[str, Any] = {
        "ruleId": rule_id,
        "message": {"text": f"{rule_id} finding"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
    }
    if level is not None:
        result["level"] = level
    return result


def _document() -> Dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "version": "2.20.0",
                        "rules": [
                            _rule("py/crit", **{"security-severity": "9.8"}),
                            _rule("py/high", **{"security-severity": "8.1"}),
                            _rule("py/medium", **{"security-severity": "5.0"}),
                            _rule("py/low", **{"security-severity": "2.0"}),
                            _rule("py/zero", **{"security-severity": "0.0"}),
                            _rule("py/quality-error", **{"problem.severity": "error"}),
                            _rule("py/quality-warn", **{"problem.severity": "warning"}),
                            _rule(
                                "py/quality-rec",
                                **{"problem.severity": "recommendation"},
                            ),
                            _rule("py/bare"),
                        ],
                    }
                },
                "results": [
                    _result("py/crit", "app.py", 1, "error"),
                    _result("py/high", "app.py", 2, "note"),
                    _result("py/medium", "app.py", 3, "error"),
                    _result("py/low", "app.py", 4, "error"),
                    _result("py/quality-error", "app.py", 5, "note"),
                    _result("py/quality-warn", "app.py", 6, "error"),
                    _result("py/quality-rec", "app.py", 7, "error"),
                    _result("py/bare", "app.py", 8, "error"),
                    _result("py/bare", "app.py", 9, "warning"),
                    _result("py/bare", "app.py", 10, "note"),
                    _result("py/bare", "app.py", 11, None),
                    _result("py/bare", "app.py", 12, "none"),
                ],
            }
        ],
    }


#: (ruleId, line) -> (ASH severity, SARIF level), written out by hand.
EXPECTED = {
    ("py/crit", 1): ("CRITICAL", "error"),
    ("py/high", 2): ("HIGH", "error"),
    ("py/medium", 3): ("MEDIUM", "warning"),
    ("py/low", 4): ("LOW", "note"),
    ("py/quality-error", 5): ("HIGH", "error"),
    ("py/quality-warn", 6): ("MEDIUM", "warning"),
    ("py/quality-rec", 7): ("LOW", "note"),
    ("py/bare", 8): ("HIGH", "error"),
    ("py/bare", 9): ("MEDIUM", "warning"),
    ("py/bare", 10): ("LOW", "note"),
    ("py/bare", 11): ("MEDIUM", "warning"),
    # An unrecognized level errs to the more severe rating.
    ("py/bare", 12): ("HIGH", "error"),
}


def _rated(report) -> Dict[tuple, tuple]:
    out = {}
    for r in report.get_all_results():
        region = r.locations[0].physicalLocation.root.region
        out[(r.ruleId, region.startLine)] = (
            getattr(r.properties, "issue_severity", None),
            getattr(r.level, "value", r.level),
        )
    return out


class FakeCodeql:
    """Stands in for _run_subprocess: records argv, writes the analyze report."""

    def __init__(
        self,
        document: Optional[Any] = None,
        create_exit: int = 0,
        analyze_exit: int = 0,
        timed_out: bool = False,
        write_report: bool = True,
        raw_report: Optional[str] = None,
        create_exit_by_language: Optional[Dict[str, int]] = None,
    ):
        self.document = _document() if document is None else document
        self.create_exit, self.analyze_exit = create_exit, analyze_exit
        self.timed_out, self.write_report = timed_out, write_report
        self.raw_report = raw_report
        self.create_exit_by_language = create_exit_by_language or {}
        self.calls: List[dict] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, timeout=None, env=None, **_):
            self.calls.append(
                {"argv": list(command), "timeout": timeout, "dir": results_dir}
            )
            if self.timed_out:
                scanner.exit_code = -9
                return {"timed_out": True}
            step = command[2]
            if step == "create":
                language = next(
                    a.split("=", 1)[1] for a in command if a.startswith("--language=")
                )
                code = self.create_exit_by_language.get(language, self.create_exit)
            else:
                code = self.analyze_exit
                if self.write_report:
                    out = next(
                        a.split("=", 1)[1] for a in command if a.startswith("--output=")
                    )
                    text = (
                        self.raw_report
                        if self.raw_report is not None
                        else json.dumps(copy.deepcopy(self.document))
                    )
                    Path(out).write_text(text, encoding="utf-8")
            scanner.exit_code = code
            return {"returncode": code, "stdout": "", "stderr": "SECRET-LINE from code"}

        return run


def _scanner(source: Path, tmp_path: Path, **options) -> CodeqlScanner:
    options.setdefault("license_terms_acknowledged", True)
    options.setdefault("languages", ["python"])
    return CodeqlScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=get_default_config(),
        ),
        config=CodeqlScannerConfig(
            enabled=True, options=CodeqlScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("print(1)\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(cs, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner: CodeqlScanner, fake: FakeCodeql, monkeypatch):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(target=Path(scanner.context.source_dir), target_type="source")


class TestCommunityPlugin:
    def test_the_module_exports_the_scanner(self):
        assert ash_codeql_plugins.ASH_SCANNERS == [CodeqlScanner]
        assert ash_codeql_plugins.ASH_REPORTERS == []

    def test_the_scanner_is_off_by_default(self):
        assert CodeqlScannerConfig().enabled is False
        assert CodeqlScannerConfig().name == "codeql"

    def test_the_terms_are_not_acknowledged_by_default(self):
        assert CodeqlScannerConfigOptions().license_terms_acknowledged is False

    def test_the_module_docstring_states_the_terms_constraint(self):
        doc = cs.__doc__ or ""
        assert "automated analysis, CI, or CD" in doc
        assert "not an Open Source Codebase" in doc
        assert "Advanced Security" in doc

    def test_declared_class_attributes(self):
        assert CodeqlScanner.python_only is False
        assert CodeqlScanner.success_exit_codes == {0, 32}
        assert CodeqlScanner.sandbox_requirements == SandboxRequirements()


class TestLicenseGate:
    def test_without_the_acknowledgement_codeql_is_never_started(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, license_terms_acknowledged=False)
        fake = FakeCodeql()
        with pytest.raises(ScannerError) as raised:
            _run(scanner, fake, monkeypatch)
        assert "license_terms_acknowledged" in str(raised.value)
        assert fake.calls == []

    def test_the_acknowledgement_lets_it_run(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeCodeql()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert len(fake.calls) == 2


class TestLanguages:
    def test_no_languages_fails_before_codeql_starts(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, languages=[])
        fake = FakeCodeql()
        with pytest.raises(ScannerError, match="languages is empty"):
            _run(scanner, fake, monkeypatch)
        assert fake.calls == []

    @pytest.mark.parametrize("name", ["go", "swift"])
    def test_a_language_that_needs_a_build_is_refused(
        self, tree, tmp_path, on_path, monkeypatch, name
    ):
        scanner = _scanner(tree, tmp_path, languages=[name])
        fake = FakeCodeql()
        with pytest.raises(ScannerError, match="needs a build"):
            _run(scanner, fake, monkeypatch)
        assert fake.calls == []

    def test_an_unknown_language_is_refused(self):
        with pytest.raises(ScannerError, match="not one this plugin runs"):
            canonical_language("cobol")

    @pytest.mark.parametrize(
        "alias, standard",
        [
            ("javascript", "javascript-typescript"),
            ("TypeScript", "javascript-typescript"),
            ("java", "java-kotlin"),
            ("kotlin", "java-kotlin"),
            ("cpp", "c-cpp"),
            ("c", "c-cpp"),
            ("python", "python"),
        ],
    )
    def test_aliases_resolve_to_the_standard_identifier(self, alias, standard):
        assert canonical_language(alias) == standard


class TestInvocation:
    def test_every_fixed_flag_and_the_paths(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path, threads=4)
        fake = FakeCodeql()
        _run(scanner, fake, monkeypatch)
        create, analyze = (c["argv"] for c in fake.calls)
        database = create[-1]
        assert create[:3] == ["codeql", "database", "create"]
        assert "--language=python" in create
        assert f"--source-root={tree.absolute().as_posix()}" in create
        assert "--build-mode=none" in create
        assert "--overwrite" in create
        assert "--threads=4" in create
        assert create[-2] == "--"
        assert analyze[:3] == ["codeql", "database", "analyze"]
        assert "--format=sarifv2.1.0" in analyze
        assert "--no-download" in analyze
        assert "--sarif-add-snippets" in analyze
        assert "--sarif-category=ash-codeql-python" in analyze
        assert "--threads=4" in analyze
        output = next(a for a in analyze if a.startswith("--output="))
        assert output.endswith("/source/python/codeql.sarif")
        assert analyze[-3:] == [
            "--",
            database,
            "codeql/python-queries:codeql-suites/python-code-scanning.qls",
        ]

    @pytest.mark.parametrize(
        "forbidden",
        [
            "--format=sarif-latest",
            "--download",
            "--command",
            "--build-mode=autobuild",
            "--build-mode=manual",
            "--codescanning-config",
            "--github-auth-stdin",
        ],
    )
    def test_flags_that_build_download_or_read_tree_config_are_never_passed(
        self, forbidden, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeCodeql()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        for call in fake.calls:
            assert not any(a.startswith(forbidden) for a in call["argv"])

    def test_each_language_gets_its_own_database_pack_and_category(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, languages=["python", "javascript"])
        fake = FakeCodeql()
        report = _run(scanner, fake, monkeypatch)
        assert len(fake.calls) == 4
        analyze_js = fake.calls[3]["argv"]
        assert "--sarif-category=ash-codeql-javascript-typescript" in analyze_js
        assert analyze_js[-1] == (
            "codeql/javascript-queries:codeql-suites/javascript-code-scanning.qls"
        )
        databases = {fake.calls[0]["argv"][-1], fake.calls[2]["argv"][-1]}
        assert len(databases) == 2
        assert len(report.runs) == 2

    def test_a_duplicate_language_is_run_once(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeCodeql()
        _run(_scanner(tree, tmp_path, languages=["java", "kotlin"]), fake, monkeypatch)
        assert len(fake.calls) == 2

    def test_an_empty_target_never_reaches_the_tool(
        self, tmp_path, on_path, monkeypatch
    ):
        empty = tmp_path / "empty"
        empty.mkdir()
        scanner = _scanner(empty, tmp_path)
        fake = FakeCodeql()
        monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
        result = scanner.scan(target=empty, target_type="source")
        assert fake.calls == []
        assert result.get_all_results() == []


class TestSeverity:
    def test_every_rating_over_the_document(self, tree, tmp_path, on_path, monkeypatch):
        report = _run(_scanner(tree, tmp_path), FakeCodeql(), monkeypatch)
        assert _rated(report) == EXPECTED

    def test_severity_and_level_always_agree(self):
        document = rate_codeql_sarif(_document())
        for result in document["runs"][0]["results"]:
            severity = result["properties"]["issue_severity"]
            assert result["level"] == cs.SEVERITY_LEVELS[severity]

    @pytest.mark.parametrize(
        "score, expected",
        [
            ("10.0", "CRITICAL"),
            ("9.0", "CRITICAL"),
            ("8.9", "HIGH"),
            ("7.0", "HIGH"),
            ("6.9", "MEDIUM"),
            ("4.0", "MEDIUM"),
            ("3.9", "LOW"),
            ("0.1", "LOW"),
        ],
    )
    def test_score_boundaries(self, score, expected):
        assert severity_for(score, "recommendation", "note") == expected

    def test_a_score_of_zero_or_text_falls_back_to_problem_severity(self):
        assert severity_for("0.0", "warning", None) == "MEDIUM"
        assert severity_for("high", "error", None) == "HIGH"

    def test_the_score_wins_over_problem_severity_and_level(self):
        assert severity_for("9.5", "recommendation", "note") == "CRITICAL"

    def test_rules_in_a_pack_extension_are_read(self):
        document = {
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "CodeQL", "rules": []},
                        "extensions": [
                            {
                                "name": "codeql/python-queries",
                                "rules": [
                                    _rule("py/ext", **{"security-severity": "7.5"})
                                ],
                            }
                        ],
                    },
                    "results": [_result("py/ext", "a.py", 1, "note")],
                }
            ]
        }
        result = rate_codeql_sarif(document)["runs"][0]["results"][0]
        assert (result["properties"]["issue_severity"], result["level"]) == (
            "HIGH",
            "error",
        )

    def test_a_result_found_by_rule_index_is_rated(self):
        document = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeQL",
                            "rules": [_rule("py/x", **{"security-severity": "2.5"})],
                        }
                    },
                    "results": [{"ruleIndex": 0, "level": "error", "message": {}}],
                }
            ]
        }
        result = rate_codeql_sarif(document)["runs"][0]["results"][0]
        assert result["properties"]["issue_severity"] == "LOW"
        assert result["level"] == "note"

    def test_negative_control_a_clean_report_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        clean = _document()
        clean["runs"][0]["results"] = []
        report = _run(_scanner(tree, tmp_path), FakeCodeql(clean), monkeypatch)
        assert report.get_all_results() == []


class TestExitStatus:
    def test_findings_do_not_change_the_exit_code(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeCodeql(analyze_exit=0), monkeypatch)
        assert len(report.get_all_results()) == len(EXPECTED)
        assert scanner.exit_code == 0

    @pytest.mark.parametrize("code", [1, 2, 33, 98, 99, 100, 137])
    def test_analyze_failures_fail_even_with_a_report_on_disk(
        self, code, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError) as raised:
            _run(scanner, FakeCodeql(analyze_exit=code), monkeypatch)
        assert "database analyze" in str(raised.value)

    def test_32_from_analyze_is_not_accepted(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError, match="database analyze"):
            _run(_scanner(tree, tmp_path), FakeCodeql(analyze_exit=32), monkeypatch)

    @pytest.mark.parametrize("code", [1, 2, 3, 33, 99, 100])
    def test_create_failures_fail_the_scan(
        self, code, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeCodeql(create_exit=code)
        with pytest.raises(ScannerError, match="database create"):
            _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert len(fake.calls) == 1

    def test_a_language_with_nothing_to_analyze_is_skipped_not_failed(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, languages=["python", "ruby"])
        fake = FakeCodeql(create_exit_by_language={"ruby": 32})
        report = _run(scanner, fake, monkeypatch)
        assert len(fake.calls) == 3
        assert scanner.targets_attempted == 1
        assert scanner.targets_failed == 0
        assert scanner.exit_code == 0
        assert len(report.runs) == 1

    def test_every_language_empty_reads_as_nothing_scanned(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeCodeql(create_exit=32), monkeypatch)
        assert report.get_all_results() == []
        assert scanner.targets_attempted == 0

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=30)
        fake = FakeCodeql(timed_out=True)
        with pytest.raises(ScannerError, match="timed out"):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 30

    def test_the_budget_is_shared_by_every_step(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        # Deadline at 160; the create step starts at 110 (50s left); the analyze
        # step starts at 200, past the deadline.
        clock = iter([100.0, 110.0, 200.0])
        monkeypatch.setattr(cs, "_now", lambda: next(clock))
        scanner = _scanner(tree, tmp_path, scan_timeout=60)
        fake = FakeCodeql()
        with pytest.raises(ScannerError, match="timed out"):
            _run(scanner, fake, monkeypatch)
        timeouts = [c["timeout"] for c in fake.calls]
        assert timeouts[0] == pytest.approx(50.0)
        assert len(fake.calls) == 1

    def test_stderr_is_not_copied_into_errors_or_the_failure(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError) as raised:
            _run(scanner, FakeCodeql(analyze_exit=2), monkeypatch)
        assert "SECRET-LINE" not in str(raised.value)
        assert not any("SECRET-LINE" in e for e in scanner.errors)
        assert "not quoted here" in str(raised.value)


class TestMalformedOutput:
    @pytest.mark.parametrize(
        "raw",
        ["not json", "[]", '{"version": "2.1.0"}', '{"runs": []}'],
    )
    def test_unusable_reports_fail_the_scan(
        self, raw, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError):
            _run(_scanner(tree, tmp_path), FakeCodeql(raw_report=raw), monkeypatch)

    def test_an_empty_report_file_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError, match="no SARIF run"):
            _run(_scanner(tree, tmp_path), FakeCodeql(raw_report=""), monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError):
            _run(_scanner(tree, tmp_path), FakeCodeql(write_report=False), monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_not_read(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeCodeql(), monkeypatch)
        with pytest.raises(ScannerError):
            _run(scanner, FakeCodeql(write_report=False), monkeypatch)


class TestDependencyCheck:
    def test_tool_absent_is_reported_missing(self, tree, tmp_path, monkeypatch):
        monkeypatch.setattr(cs, "find_executable", lambda cmd: None)
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is False

    def test_tool_present(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True

    def test_a_scan_with_the_tool_absent_does_not_start_it(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(cs, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        fake = FakeCodeql()
        result = _run(scanner, fake, monkeypatch)
        assert result is False
        assert fake.calls == []

    def test_the_scanner_declares_no_installer(self, tree, tmp_path):
        assert not _scanner(tree, tmp_path).custom_install_commands


class TestSandboxDeclaration:
    def test_the_strict_default_is_declared(self):
        requirements = CodeqlScanner.sandbox_requirements
        assert requirements == SandboxRequirements()
        assert not requirements.network
