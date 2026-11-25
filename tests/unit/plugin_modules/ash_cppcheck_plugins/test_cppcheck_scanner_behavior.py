# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CppcheckScanner: the invocation, the exit status, and the report rating.

The subprocess is replaced with a fake that writes SARIF where the argv says, so the
tests run on every platform without Cppcheck. The SARIF below is shaped from
Cppcheck's own writer (lib/sarifreport.cpp): ``error`` and ``warning`` severities
both come out as level ``error``, style, performance and portability as ``warning``,
information as ``note``, and ``driver.semanticVersion`` is the only version field.
That synthetic SARIF drives the invocation and failure-mode rows. The severity rows
over a real report use the captured 2.17.1 files in
tests/test_data/scanners/cppcheck/captured/, which show that Cppcheck writes level
``warning`` for its error and warning severities and ``note`` for the rest, so the
synthetic ``error`` level exercises only the defensive branch of the mapping.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_cppcheck_plugins
from automated_security_helper.plugin_modules.ash_cppcheck_plugins import (
    cppcheck_scanner as cs,
)
from automated_security_helper.plugin_modules.ash_cppcheck_plugins.cppcheck_scanner import (
    CppcheckScanner,
    CppcheckScannerConfig,
    CppcheckScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit


def _result(rule: str, level: Optional[str], uri: str, line: int) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ruleId": rule,
        "message": {"text": f"{rule} finding"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": line,
                        "endLine": line,
                        "startColumn": 1,
                        "endColumn": 1,
                    },
                }
            }
        ],
    }
    if level is not None:
        result["level"] = level
    return result


def _sarif(results: List[Dict[str, Any]]) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Cppcheck",
                            "semanticVersion": "2.17.1",
                            "informationUri": "https://cppcheck.sourceforge.io",
                            "rules": [],
                        }
                    },
                    "results": results,
                }
            ],
        }
    )


_CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "cppcheck"
    / "captured"
)
#: Real Cppcheck 2.17.1 output; see captured/README.md for the argv and inputs.
CAPTURED_POSITIVE = (_CAPTURED / "positive.sarif").read_text(encoding="utf-8")
CAPTURED_NEGATIVE = (_CAPTURED / "negative.sarif").read_text(encoding="utf-8")

#: error (HIGH), a style finding (MEDIUM), an information note (LOW).
POSITIVE = _sarif(
    [
        _result("nullPointer", "error", "./src/main.c", 12),
        _result("unusedVariable", "warning", "src/util.cpp", 7),
        _result("checkersReport", "note", "src/util.cpp", 9),
    ]
)
POSITIVE_EXPECTED = [
    ("nullPointer", "error", "HIGH", "src/main.c", 12),
    ("unusedVariable", "warning", "MEDIUM", "src/util.cpp", 7),
    ("checkersReport", "note", "LOW", "src/util.cpp", 9),
]
NEGATIVE = _sarif([])


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


class FakeCppcheck:
    """Stands in for _run_subprocess: records argv, writes the report it is given."""

    def __init__(
        self,
        sarif_text: Optional[str] = POSITIVE,
        exit_code: int = 2,
        timed_out: bool = False,
        stderr: str = "",
    ):
        self.sarif_text, self.exit_code = sarif_text, exit_code
        self.timed_out, self.stderr = timed_out, stderr
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            if self.timed_out:
                return {"timed_out": True}
            out = next(a for a in command if a.startswith("--output-file="))
            path = Path(out.split("=", 1)[1])
            if self.sarif_text is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(self.sarif_text, encoding="utf-8")
            scanner.exit_code = self.exit_code
            return {"returncode": self.exit_code, "stdout": "", "stderr": self.stderr}

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(source: Path, tmp_path: Path, **options) -> CppcheckScanner:
    output = tmp_path / "out"
    return CppcheckScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=get_default_config(),
        ),
        config=CppcheckScannerConfig(
            enabled=True, options=CppcheckScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "src").mkdir(parents=True)
    (src / "src" / "main.c").write_text("int main(void){return 0;}\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(cs, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner, fake, monkeypatch, target=None, target_type="source"):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type=target_type
    )


class TestCommunityPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert CppcheckScannerConfig().enabled is True
        assert CppcheckScannerConfig().name == "cppcheck"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "cppcheck")

    def test_the_module_exports_the_scanner(self):
        assert ash_cppcheck_plugins.ASH_SCANNERS == [CppcheckScanner]
        assert ash_cppcheck_plugins.ASH_REPORTERS == []

    def test_declared_scan_properties(self):
        assert CppcheckScanner.python_only is False
        assert CppcheckScanner.success_exit_codes == {0, 2}
        assert CppcheckScanner.sandbox_requirements == SandboxRequirements()


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCppcheck()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[0] == "cppcheck"
        assert "--output-format=sarif" in argv
        assert "--error-exitcode=2" in argv
        assert "--enable=warning,style,performance,portability" in argv
        assert "--quiet" in argv
        assert any(a.startswith("--output-file=") for a in argv)
        # The source target is "." and is the last token.
        assert argv[-1] == "."

    def test_every_option_is_one_token(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCppcheck()
        _run(scanner, fake, monkeypatch)
        for flag in (
            "--output-format",
            "--output-file",
            "--error-exitcode",
            "--enable",
        ):
            assert flag not in fake.argv, f"{flag} must carry its value with ="

    def test_a_converted_target_is_an_absolute_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        converted = tmp_path / "converted"
        converted.mkdir()
        (converted / "a.c").write_text("int x;\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeCppcheck(sarif_text=NEGATIVE, exit_code=0)
        _run(scanner, fake, monkeypatch, target=converted, target_type="converted")
        assert fake.argv[-1] == converted.absolute().as_posix()
        assert fake.argv[-1].startswith("/") or ":" in fake.argv[-1]

    @pytest.mark.parametrize(
        "forbidden",
        [
            "--inline-suppr",
            "--project",
            "--addon",
            "--library",
            "--suppressions-list",
            "--suppress-xml",
            "--rule-file",
            "--enable=all",
            "--enable=information",
            "--enable=missingInclude",
        ],
    )
    def test_flags_that_read_the_tree_or_hide_findings_are_never_passed(
        self, tree, tmp_path, on_path, monkeypatch, forbidden
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCppcheck()
        _run(scanner, fake, monkeypatch)
        assert not any(
            a == forbidden or a.startswith(forbidden + "=") for a in fake.argv
        )

    def test_a_missing_target_never_reaches_the_tool(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCppcheck()
        _run(scanner, fake, monkeypatch, target=tmp_path / "nowhere")
        assert fake.calls == []

    def test_the_timeout_reaches_the_subprocess(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=7)
        fake = FakeCppcheck()
        _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 7


class TestReport:
    def test_the_positive_report_is_rated_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeCppcheck(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_the_clean_report_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(
            scanner, FakeCppcheck(sarif_text=NEGATIVE, exit_code=0), monkeypatch
        )
        assert _findings(report) == []

    @pytest.mark.parametrize(
        "level,expected",
        [
            ("error", ("error", "HIGH")),
            ("warning", ("warning", "MEDIUM")),
            ("note", ("note", "LOW")),
            (None, ("warning", "MEDIUM")),
        ],
    )
    def test_level_and_severity_agree_row_by_row(
        self, tree, tmp_path, on_path, monkeypatch, level, expected
    ):
        scanner = _scanner(tree, tmp_path)
        text = _sarif([_result("someRule", level, "a.c", 1)])
        report = _run(scanner, FakeCppcheck(sarif_text=text), monkeypatch)
        (finding,) = _findings(report)
        assert (finding[1], finding[2]) == expected

    def test_a_real_captured_report_is_rated_by_security_severity(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """Severity over a REAL Cppcheck 2.17.1 report (checklist row 18).

        Every result carries level ``warning``; the two security rules carry
        security-severity 9.9 on their rule entry and rate HIGH, the style rule
        has none and stays MEDIUM.
        """
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeCppcheck(sarif_text=CAPTURED_POSITIVE), monkeypatch)
        assert sorted(_findings(report)) == sorted(
            [
                ("arrayIndexOutOfBounds", "error", "HIGH", "bad.c", 5),
                ("memleak", "error", "HIGH", "bad.c", 8),
                ("unreadVariable", "warning", "MEDIUM", "bad.c", 5),
            ]
        )
        assert scanner.exit_code == 2

    def test_a_real_captured_clean_report_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(
            scanner,
            FakeCppcheck(sarif_text=CAPTURED_NEGATIVE, exit_code=0),
            monkeypatch,
        )
        assert _findings(report) == []

    @pytest.mark.parametrize(
        "score,expected",
        [
            (9.9, ("error", "HIGH")),
            (7.0, ("error", "HIGH")),
            (6.9, ("warning", "MEDIUM")),
            ("9.9", ("warning", "MEDIUM")),
            (True, ("warning", "MEDIUM")),
            (None, ("warning", "MEDIUM")),
        ],
    )
    def test_security_severity_raises_a_warning_only_when_numeric_and_high(
        self, tree, tmp_path, on_path, monkeypatch, score, expected
    ):
        doc = json.loads(_sarif([_result("someRule", "warning", "a.c", 1)]))
        props: Dict[str, Any] = {"precision": "high"}
        if score is not None:
            props["security-severity"] = score
        doc["runs"][0]["tool"]["driver"]["rules"] = [
            {"id": "someRule", "properties": props}
        ]
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeCppcheck(sarif_text=json.dumps(doc)), monkeypatch)
        (finding,) = _findings(report)
        assert (finding[1], finding[2]) == expected

    def test_results_are_failures(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeCppcheck(), monkeypatch)
        for result in report.get_all_results():
            assert getattr(result.kind, "value", result.kind) == "fail"

    def test_leading_dot_slash_is_stripped_from_uris(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeCppcheck(), monkeypatch)
        assert all(not f[3].startswith("./") for f in _findings(report))

    def test_the_report_round_trips_as_sarif(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeCppcheck(), monkeypatch)
        assert SarifReport.model_validate(report.model_dump(by_alias=True, mode="json"))


class TestFailureModes:
    @pytest.mark.parametrize("code", [1, 126, 137])
    def test_any_exit_but_0_and_2_fails_even_with_a_report_on_disk(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeCppcheck(exit_code=code), monkeypatch)

    def test_nonzero_exit_with_findings_is_a_success(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeCppcheck(exit_code=2), monkeypatch)
        assert scanner.exit_code == 2
        assert scanner._exit_code_accepted()
        assert len(_findings(report)) == 3

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=5)
        fake = FakeCppcheck(timed_out=True)
        with pytest.raises(ScannerError, match="timed out"):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 5

    @pytest.mark.parametrize(
        "text",
        ["", "not json at all", "[1, 2]", "{}", '{"version": "2.1.0", "runs": []}'],
    )
    def test_malformed_or_empty_output_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch, text
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeCppcheck(sarif_text=text, exit_code=0), monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeCppcheck(sarif_text=None, exit_code=0), monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_removed_first(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        first = FakeCppcheck()
        _run(scanner, first, monkeypatch)
        report = Path(
            next(a for a in first.argv if a.startswith("--output-file=")).split("=", 1)[
                1
            ]
        )
        assert report.exists()
        with pytest.raises(ScannerError):
            _run(scanner, FakeCppcheck(sarif_text=None, exit_code=0), monkeypatch)
        assert not report.exists()

    def test_the_tools_stderr_is_not_copied_into_the_scans_errors(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner._process_command_response(
            {"returncode": 0, "stdout": "", "stderr": "error: PLANTED-SOURCE-LINE"}
        )
        assert not any("PLANTED-SOURCE-LINE" in line for line in scanner.errors)

    def test_the_failure_message_names_the_log_and_does_not_quote_it(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.exit_code = 1
        results = tmp_path / "out" / "source" / "cppcheck.sarif"
        message = scanner._describe_scan_failure(ScannerError("boom"), results)
        assert "stderr.log" in message
        assert "not quoted" in message

    def test_a_failure_before_the_tool_started_says_so(self, tree, tmp_path, on_path):
        scanner = _scanner(tree, tmp_path)
        message = scanner._describe_scan_failure(
            ScannerError("boom"), None, tool_started=False
        )
        assert "was not started" in message


class TestDependencyCheck:
    def test_tool_absent_is_reported_as_unsatisfied(self, tree, tmp_path, monkeypatch):
        monkeypatch.setattr(cs, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False

    def test_tool_absent_means_scan_does_not_run_the_tool(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(cs, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        fake = FakeCppcheck()
        _run(scanner, fake, monkeypatch)
        assert fake.calls == []

    def test_a_present_binary_satisfies_them(self, tree, tmp_path, on_path):
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is True

    def test_a_recorded_unavailable_reason_wins(self, tree, tmp_path, on_path):
        scanner = _scanner(tree, tmp_path)
        scanner.dependency_unavailable_reason = "refused"
        assert scanner.validate_plugin_dependencies() is False


class TestInstall:
    @pytest.mark.parametrize(
        "platform,arch,manager",
        [
            ("linux", "amd64", "apt-get"),
            ("linux", "arm64", "apt-get"),
            ("darwin", "amd64", "brew"),
            ("darwin", "arm64", "brew"),
        ],
    )
    def test_install_commands_cover_every_declared_platform(
        self, tmp_path, platform, arch, manager
    ):
        scanner = _scanner(tmp_path, tmp_path)
        commands = scanner.get_installation_commands(platform, arch)
        assert commands, f"no install command for {platform}/{arch}"
        assert manager in commands[0]
        assert "cppcheck" in commands[0]
