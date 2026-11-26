# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CredSweeperScanner: the invocation, the report conversion and failure handling.

The scan() tests replace the subprocess with a fake that writes a report in the shape
the CredSweeper guide documents (a JSON array; per finding ``rule``, ``severity``,
``confidence``, ``ml_probability`` and ``line_data_list`` with ``path``, ``line_num``,
``line``, ``value``), so they run on every platform without the tool. The
``value`` fields hold a placeholder, never a credential-shaped string.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_credsweeper_plugins
from automated_security_helper.plugin_modules.ash_credsweeper_plugins import (
    credsweeper_scanner as cs,
)
from automated_security_helper.plugin_modules.ash_credsweeper_plugins.credsweeper_scanner import (
    CredSweeperScanner,
    CredSweeperScannerConfig,
    CredSweeperScannerConfigOptions,
    convert_credsweeper_report,
    rate_confidence,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

PLACEHOLDER = "PLACEHOLDER_NOT_A_CREDENTIAL"


def _finding(
    rule: str = "Password",
    confidence: str = "moderate",
    path: str = "app.py",
    line_num: int = 4,
    severity: str = "medium",
    probability: Optional[float] = 0.79,
) -> Dict[str, Any]:
    return {
        "rule": rule,
        "severity": severity,
        "confidence": confidence,
        "ml_probability": probability,
        "line_data_list": [
            {
                "line": PLACEHOLDER,
                "line_num": line_num,
                "path": path,
                "info": "FILE:" + path,
                "variable": PLACEHOLDER,
                "variable_start": 0,
                "variable_end": 8,
                "value": PLACEHOLDER,
                "value_start": 11,
                "value_end": 40,
                "entropy": 3.1,
            }
        ],
    }


POSITIVE = [
    _finding("Password", "strong", "app.py", 4, "high", 0.97),
    _finding("Token", "moderate", "services/settings.py", 3, "medium", 0.71),
    _finding("Key", "weak", "./notes.txt", 9, "low", 0.52),
]

#: Written out by hand from POSITIVE: (ruleId, SARIF level, ASH severity, uri, line).
POSITIVE_EXPECTED = [
    ("Password", "error", "HIGH", "app.py", 4),
    ("Token", "warning", "MEDIUM", "services/settings.py", 3),
    ("Key", "note", "LOW", "notes.txt", 9),
]


def _findings(report: SarifReport) -> List[tuple]:
    out = []
    for r in report.get_all_results():
        loc = r.locations[0].physicalLocation.root
        out.append(
            (
                r.ruleId,
                getattr(r.level, "value", r.level),
                getattr(r.properties, "issue_severity", None),
                loc.artifactLocation.uri,
                loc.region.startLine,
            )
        )
    return out


class FakeCredSweeper:
    """Stands in for _run_subprocess: records argv, writes a report."""

    def __init__(
        self,
        report: Any = None,
        report_text: Optional[str] = None,
        write_report: bool = True,
        exit_code: int = 0,
        response_extra: Optional[Dict[str, Any]] = None,
    ):
        self.report = POSITIVE if report is None else report
        self.report_text = report_text
        self.write_report = write_report
        self.exit_code = exit_code
        self.response_extra = response_extra or {}
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            if self.write_report:
                arg = next(a for a in command if a.startswith("--save-json="))
                path = Path(arg.split("=", 1)[1])
                path.parent.mkdir(parents=True, exist_ok=True)
                text = (
                    self.report_text
                    if self.report_text is not None
                    else json.dumps(self.report)
                )
                path.write_text(text, encoding="utf-8")
            scanner.exit_code = self.exit_code
            return {
                "returncode": self.exit_code,
                "stdout": "",
                "stderr": "",
                **self.response_extra,
            }

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(source: Path, tmp_path: Path, **options) -> CredSweeperScanner:
    output = tmp_path / "out"
    return CredSweeperScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=get_default_config(),
        ),
        config=CredSweeperScannerConfig(
            enabled=True, options=CredSweeperScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "services").mkdir(parents=True)
    (src / "app.py").write_text("print(1)\n")
    (src / "services" / "settings.py").write_text("DEBUG = False\n")
    return src


def _run(scanner, fake, monkeypatch, *, deps: bool = True, target=None):
    monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: deps)
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type="source"
    )


class TestCommunityPlugin:
    def test_the_module_exports_the_scanner(self):
        assert ash_credsweeper_plugins.ASH_SCANNERS == [CredSweeperScanner]
        assert ash_credsweeper_plugins.ASH_REPORTERS == []

    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert CredSweeperScannerConfig().enabled is True
        assert CredSweeperScannerConfig().name == "credsweeper"

    def test_class_declarations(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        assert scanner.command == "credsweeper"
        assert scanner.use_uv_tool is True
        assert CredSweeperScanner.success_exit_codes == {0}
        assert CredSweeperScanner.python_only is False
        assert CredSweeperScanner.offline_strategy.name == "BUNDLED"


class TestSeverity:
    @pytest.mark.parametrize(
        "confidence,expected",
        [
            ("strong", ("HIGH", "error")),
            ("moderate", ("MEDIUM", "warning")),
            ("weak", ("LOW", "note")),
            ("STRONG", ("HIGH", "error")),
            ("unheard-of", ("HIGH", "error")),
            (None, ("HIGH", "error")),
            (3, ("HIGH", "error")),
        ],
    )
    def test_confidence_rows(self, confidence, expected):
        assert rate_confidence(confidence) == expected

    def test_issue_severity_and_level_agree_on_every_result(self, tree):
        doc = convert_credsweeper_report(POSITIVE, tree)
        report = SarifReport.model_validate(doc)
        assert _findings(report) == POSITIVE_EXPECTED


class TestConversion:
    def test_positive_report_is_rated_and_located(self, tree):
        report = SarifReport.model_validate(convert_credsweeper_report(POSITIVE, tree))
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_an_empty_array_has_a_run_and_no_findings(self, tree):
        report = SarifReport.model_validate(convert_credsweeper_report([], tree))
        assert len(report.runs) == 1
        assert report.get_all_results() == []

    def test_the_credential_text_never_reaches_the_sarif(self, tree):
        text = json.dumps(convert_credsweeper_report(POSITIVE, tree))
        assert PLACEHOLDER not in text
        assert cs.REDACTED in text

    def test_an_absolute_path_under_the_source_becomes_relative(self, tree):
        finding = _finding(path=(tree / "app.py").as_posix())
        report = SarifReport.model_validate(convert_credsweeper_report([finding], tree))
        assert _findings(report)[0][3] == "app.py"

    def test_a_finding_without_a_line_has_no_region(self, tree):
        finding = _finding()
        finding["line_data_list"][0]["line_num"] = 0
        doc = convert_credsweeper_report([finding], tree)
        physical = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert "region" not in physical

    @pytest.mark.parametrize(
        "bad",
        [{"rule": "x"}, "text", 7, None, ["not an object"]],
    )
    def test_malformed_documents_fail_the_scan_not_clean(self, tree, bad):
        with pytest.raises(ScannerError):
            convert_credsweeper_report(bad, tree)


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(self, tree, tmp_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCredSweeper()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[0] == "credsweeper"
        assert "--path=." in argv
        assert any(
            a.startswith("--save-json=") and a.endswith("/source/credsweeper.json")
            for a in argv
        )
        for flag in ("--no-stdout", "--no-color", "--no-progress", "--hashed"):
            assert flag in argv
        assert "--no-error" in argv
        assert "--error" not in argv

    def test_every_option_is_one_token(self, tree, tmp_path, monkeypatch):
        fake = FakeCredSweeper()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        for token in fake.argv[1:]:
            assert token.startswith("--")
            assert "=" in token or token in {
                "--no-stdout",
                "--no-color",
                "--no-progress",
                "--hashed",
                "--no-error",
            }

    @pytest.mark.parametrize(
        "flag",
        [
            "--config",
            "--rules",
            "--denylist",
            "--skip_ignored",
            "--ml_threshold",
            "--ml_model",
            "--ml_config",
            "--severity",
            "--confidence",
            "--git",
            "--diff_path",
            "--doc",
            "--depth",
            "--log_config",
        ],
    )
    def test_flags_that_read_the_tree_or_hide_findings_are_never_passed(
        self, tree, tmp_path, monkeypatch, flag
    ):
        fake = FakeCredSweeper()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert not any(a == flag or a.startswith(flag + "=") for a in fake.argv)

    def test_a_subdirectory_target_is_passed_absolute(
        self, tree, tmp_path, monkeypatch
    ):
        fake = FakeCredSweeper()
        _run(
            _scanner(tree, tmp_path),
            fake,
            monkeypatch,
            target=tree / "services",
        )
        assert f"--path={(tree / 'services').absolute().as_posix()}" in fake.argv

    def test_a_missing_target_never_reaches_the_tool(self, tree, tmp_path, monkeypatch):
        fake = FakeCredSweeper()
        _run(_scanner(tree, tmp_path), fake, monkeypatch, target=tmp_path / "gone")
        assert fake.calls == []

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeCredSweeper(), monkeypatch)
        stale = Path(scanner.results_dir) / "source" / "credsweeper.json"
        assert stale.exists()
        fake = FakeCredSweeper(write_report=False)
        with pytest.raises(ScannerError):
            _run(scanner, fake, monkeypatch)
        assert not stale.exists()

    def test_the_scan_timeout_reaches_the_subprocess(self, tree, tmp_path, monkeypatch):
        fake = FakeCredSweeper()
        scanner = _scanner(tree, tmp_path, scan_timeout=77)
        _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 77


class TestScan:
    def test_happy_path_returns_the_findings(self, tree, tmp_path, monkeypatch):
        report = _run(_scanner(tree, tmp_path), FakeCredSweeper(), monkeypatch)
        assert isinstance(report, SarifReport)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_clean_run_has_no_findings(self, tree, tmp_path, monkeypatch):
        report = _run(_scanner(tree, tmp_path), FakeCredSweeper(report=[]), monkeypatch)
        assert isinstance(report, SarifReport)
        assert report.get_all_results() == []

    @pytest.mark.parametrize("code", [1, 2, 126, 137])
    def test_nonzero_exit_fails_even_with_findings_on_disk(
        self, tree, tmp_path, monkeypatch, code
    ):
        with pytest.raises(ScannerError, match="credsweeper"):
            _run(
                _scanner(tree, tmp_path),
                FakeCredSweeper(exit_code=code),
                monkeypatch,
            )

    def test_a_timeout_fails_the_scan_and_says_so(self, tree, tmp_path, monkeypatch):
        fake = FakeCredSweeper(
            write_report=False, exit_code=0, response_extra={"timed_out": True}
        )
        with pytest.raises(ScannerError, match="timed out"):
            _run(_scanner(tree, tmp_path, scan_timeout=5), fake, monkeypatch)

    @pytest.mark.parametrize(
        "text",
        ["{not json", '{"rule": "x"}', '"a string"', "[1, 2]"],
    )
    def test_malformed_output_fails_the_scan(self, tree, tmp_path, monkeypatch, text):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path),
                FakeCredSweeper(report_text=text),
                monkeypatch,
            )

    def test_an_empty_report_file_fails_the_scan(self, tree, tmp_path, monkeypatch):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path),
                FakeCredSweeper(report_text=""),
                monkeypatch,
            )

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, monkeypatch
    ):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path),
                FakeCredSweeper(write_report=False),
                monkeypatch,
            )

    def test_stderr_is_not_copied_into_the_scanner_errors(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCredSweeper(response_extra={"stderr": "quoted tree text XYZZY"})
        _run(scanner, fake, monkeypatch)
        assert not any("XYZZY" in line for line in scanner.errors)

    def test_tool_absent_skips_the_scan_without_starting_the_tool(
        self, tree, tmp_path, monkeypatch
    ):
        fake = FakeCredSweeper()
        result = _run(_scanner(tree, tmp_path), fake, monkeypatch, deps=False)
        assert result is False
        assert fake.calls == []


class TestDependencyCheck:
    def test_a_missing_tool_is_unavailable_with_the_install_hint(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        monkeypatch.setattr(scanner, "resolve_deferred_tool_version", lambda: None)
        monkeypatch.setattr(scanner, "_validate_uv_tool_availability", lambda: False)
        monkeypatch.setattr(cs, "get_uv_tool_command", lambda *a, **k: None)
        assert scanner.validate_plugin_dependencies() is False
        reason = scanner.dependency_unavailable_reason
        assert reason is not None
        assert "--tool credsweeper" in reason
        assert "ash_credsweeper_plugins" in reason

    def test_a_recorded_unavailable_reason_stays_false(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        scanner.dependency_unavailable_reason = "recorded earlier"
        assert scanner.validate_plugin_dependencies() is False

    def test_a_copy_on_path_is_used_when_uv_is_missing(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        monkeypatch.setattr(scanner, "resolve_deferred_tool_version", lambda: None)
        monkeypatch.setattr(scanner, "_validate_uv_tool_availability", lambda: False)
        monkeypatch.setattr(
            cs, "get_uv_tool_command", lambda *a, **k: ["/fake/bin/credsweeper"]
        )
        assert scanner.validate_plugin_dependencies() is True
        assert scanner.use_uv_tool is False


class TestInstall:
    def test_default_constraint_and_python_request(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        assert (
            scanner._get_tool_version_constraint()
            == cs.CREDSWEEPER_DEFAULT_VERSION_CONSTRAINT
        )
        assert scanner._get_tool_python_request() == cs.CREDSWEEPER_PYTHON_REQUEST

    def test_the_constraint_is_a_bounded_range_not_floating(self):
        assert "<" in cs.CREDSWEEPER_DEFAULT_VERSION_CONSTRAINT
        assert cs.CREDSWEEPER_DEFAULT_VERSION_CONSTRAINT.startswith(">=")

    def test_a_configured_tool_version_wins(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path, tool_version="==1.19.6")
        assert scanner._get_tool_version_constraint() == "==1.19.6"
