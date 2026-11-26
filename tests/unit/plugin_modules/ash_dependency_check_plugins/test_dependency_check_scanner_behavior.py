# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""DependencyCheckScanner: the invocation, the severity rating and the report.

The subprocess is replaced by a fake that writes a SARIF report shaped like the one
the tool's own template (``sarifReport.vsl``, release v13.0.0) produces: the severity
sits on the rules, every result says ``warning``, and every URI is an absolute
``file://`` URI. The report is built here, not captured from a run, because no host
with Java was available; the integration notes in the plugin README say so.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_dependency_check_plugins
from automated_security_helper.plugin_modules.ash_dependency_check_plugins import (
    dependency_check_scanner as ds,
)
from automated_security_helper.plugin_modules.ash_dependency_check_plugins.dependency_check_scanner import (
    DEPENDENCY_CHECK_SHA256,
    DEPENDENCY_CHECK_URL,
    DEPENDENCY_CHECK_VERSION,
    DependencyCheckScanner,
    DependencyCheckScannerConfig,
    DependencyCheckScannerConfigOptions,
    rate_rule,
    severity_for_score,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

#: An obviously fake NVD key, used only to prove it never reaches the argv.
FAKE_KEY = "fake-nvd-key-for-tests"

#: Each rule: id, properties. Written by hand from the template's property names.
RULES = [
    ("CVE-2021-0001", {"cvssv3_baseScore": 10.0, "security-severity": "10.0"}),
    ("CVE-2021-0002", {"cvssv3_baseScore": 7.5, "security-severity": "7.5"}),
    ("CVE-2021-0003", {"cvssv3_baseScore": 5.3, "security-severity": "5.3"}),
    ("CVE-2021-0004", {"cvssv3_baseScore": 2.1, "security-severity": "2.1"}),
    ("CVE-2021-0005", {"cvssv2_score": 9.3, "cvssv2_severity": "HIGH"}),
    ("CVE-2021-0006", {}),
]

#: (ruleId, file under the source dir), one result per rule, in this order.
RESULT_FILES = [
    ("CVE-2021-0001", "lib/log4j-core-2.14.1.jar"),
    ("CVE-2021-0002", "lib/jackson-databind-2.9.0.jar"),
    ("CVE-2021-0003", "web/package-lock.json"),
    ("CVE-2021-0004", "web/package-lock.json"),
    ("CVE-2021-0005", "requirements.txt"),
    ("CVE-2021-0006", "requirements.txt"),
]

#: What the report above must produce, written out by hand: ruleId, SARIF level,
#: ASH severity, source-relative URI.
EXPECTED = [
    ("CVE-2021-0001", "error", "CRITICAL", "lib/log4j-core-2.14.1.jar"),
    ("CVE-2021-0002", "error", "HIGH", "lib/jackson-databind-2.9.0.jar"),
    ("CVE-2021-0003", "warning", "MEDIUM", "web/package-lock.json"),
    ("CVE-2021-0004", "note", "LOW", "web/package-lock.json"),
    ("CVE-2021-0005", "error", "HIGH", "requirements.txt"),
    ("CVE-2021-0006", "warning", "MEDIUM", "requirements.txt"),
]


def sarif_for(source: Path, *, with_results: bool = True) -> Dict[str, Any]:
    """A report shaped like ``sarifReport.vsl``'s output, over files in ``source``."""
    base = source.absolute().as_posix()
    results = []
    if with_results:
        for rule_id, name in RESULT_FILES:
            results.append(
                {
                    "ruleId": rule_id,
                    "level": "warning",
                    "message": {"text": f"{rule_id} - a vulnerability"},
                    "partialFingerprints": {"vulnerabilityHash": "0" * 32},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": f"file://{base}/{name}",
                                    "index": 0,
                                }
                            }
                        }
                    ],
                }
            )
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dependency-check",
                        "version": DEPENDENCY_CHECK_VERSION,
                        "informationUri": "https://dependency-check.github.io/DependencyCheck/",
                        "rules": [
                            {
                                "id": rule_id,
                                "shortDescription": {"text": rule_id},
                                "fullDescription": {"text": rule_id},
                                "properties": {**props, "source": "NVD"},
                            }
                            for rule_id, props in RULES
                        ],
                    }
                },
                "artifacts": [
                    {"location": {"uri": f"file://{base}/lib/log4j-core-2.14.1.jar"}}
                ],
                "results": results,
            }
        ],
    }


class FakeDependencyCheck:
    """Stands in for _run_subprocess: records the call, writes the report."""

    def __init__(
        self,
        source: Path,
        exit_code: int = 0,
        write_report: bool = True,
        sarif_text: Optional[str] = None,
        clean: bool = False,
        stderr: str = "",
    ):
        self.source, self.exit_code = source, exit_code
        self.write_report, self.sarif_text = write_report, sarif_text
        self.clean, self.stderr = clean, stderr
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            properties = next(
                (a for a in command if a.startswith("--propertyfile=")), None
            )
            self.calls.append(
                {
                    "argv": list(command),
                    "env": env,
                    "timeout": timeout,
                    "cwd": cwd,
                    # Read now: the directory is removed with the run.
                    "properties": (
                        Path(properties.split("=", 1)[1]).read_text()
                        if properties
                        else None
                    ),
                    "properties_mode": (
                        stat.S_IMODE(os.stat(properties.split("=", 1)[1]).st_mode)
                        if properties
                        else None
                    ),
                }
            )
            out = next(a for a in command if a.startswith("--out="))
            path = Path(out.split("=", 1)[1]) / ds.REPORT_NAME
            if self.write_report:
                path.parent.mkdir(parents=True, exist_ok=True)
                text = self.sarif_text
                if text is None:
                    text = json.dumps(
                        sarif_for(self.source, with_results=not self.clean)
                    )
                path.write_text(text, encoding="utf-8")
            scanner.exit_code = self.exit_code
            return {"returncode": self.exit_code, "stdout": "", "stderr": self.stderr}

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(
    source: Path, tmp_path: Path, output_dir: Optional[Path] = None
) -> DependencyCheckScanner:
    output = output_dir or tmp_path / "out"
    return DependencyCheckScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=get_default_config(),
        ),
        config=DependencyCheckScannerConfig(enabled=True),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "lib").mkdir(parents=True)
    (src / "web").mkdir()
    (src / "lib" / "log4j-core-2.14.1.jar").write_bytes(b"PK")
    (src / "requirements.txt").write_text("flask==0.1\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(ds, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


@pytest.fixture(autouse=True)
def no_nvd_key(monkeypatch):
    monkeypatch.delenv(ds.NVD_API_KEY_ENV, raising=False)


def _run(scanner, fake, monkeypatch, target=None, target_type="source"):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type=target_type
    )


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
            )
        )
    return out


class TestCommunityPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert DependencyCheckScannerConfig().enabled is True
        assert DependencyCheckScannerConfig().name == "dependency-check"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "dependency-check")
        assert not hasattr(get_default_config().scanners, "dependency_check")

    def test_the_module_exports_the_scanner(self):
        assert ash_dependency_check_plugins.ASH_SCANNERS == [DependencyCheckScanner]
        assert ash_dependency_check_plugins.ASH_REPORTERS == []

    def test_no_option_can_point_the_tool_at_a_file_or_hide_findings(self):
        from automated_security_helper.base.options import ScannerOptionsBase

        assert set(DependencyCheckScannerConfigOptions.model_fields) == set(
            ScannerOptionsBase.model_fields
        )

    def test_class_declarations(self):
        from automated_security_helper.core.enums import OfflineStrategy
        from automated_security_helper.utils.sandbox.policy import SandboxRequirements

        assert DependencyCheckScanner.python_only is False
        assert DependencyCheckScanner.offline_strategy is OfflineStrategy.SKIP_OFFLINE
        assert DependencyCheckScanner.success_exit_codes == {0}
        requirements = DependencyCheckScanner.sandbox_requirements
        assert isinstance(requirements, SandboxRequirements)
        assert requirements.network is True
        assert ds.NVD_API_KEY_ENV in requirements.env_names


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDependencyCheck(tree)
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[0] == "dependency-check"
        for expected in ("--format=SARIF", "--disableOssIndex", "--scan=."):
            assert expected in argv
        out = next(a for a in argv if a.startswith("--out="))
        assert out.endswith("/source")
        assert fake.calls[0]["cwd"] is None, "the run starts in the source directory"

    def test_every_option_is_one_token(self, tree, tmp_path, on_path, monkeypatch):
        """``--scan .`` would be two tokens; ``--format SARIF`` too."""
        scanner = _scanner(tree, tmp_path)
        fake = FakeDependencyCheck(tree)
        _run(scanner, fake, monkeypatch)
        for flag in ("--scan", "--out", "--format", "--exclude", "--propertyfile"):
            assert flag not in fake.argv
        assert "." not in fake.argv and "SARIF" not in fake.argv

    @pytest.mark.parametrize(
        "forbidden",
        [
            "--failOnCVSS",
            "--junitFailOnCVSS",
            "--noupdate",
            "--purge",
            "--updateonly",
            "--suppression",
            "--hints",
            "--enableExperimental",
            "--enableNexus",
            "--enableArtifactory",
            "--nvdApiKey",
            "--nvdPassword",
            "--nvdBearerToken",
            "--connectionString",
            "--dbPassword",
        ],
    )
    def test_flags_that_hide_findings_read_the_tree_or_carry_a_secret_are_never_passed(
        self, tree, tmp_path, on_path, monkeypatch, forbidden
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDependencyCheck(tree)
        _run(scanner, fake, monkeypatch)
        assert not any(
            a == forbidden or a.startswith(f"{forbidden}=") for a in fake.argv
        )

    def test_the_converted_target_is_an_absolute_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "x.py").write_text("print(1)\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeDependencyCheck(tree, clean=True)
        _run(scanner, fake, monkeypatch, target=converted, target_type="converted")
        assert f"--scan={converted.absolute().as_posix()}" in fake.argv

    def test_ashs_output_directory_inside_the_tree_is_excluded(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, output_dir=tree / ".ash" / "ash_output")
        fake = FakeDependencyCheck(tree)
        _run(scanner, fake, monkeypatch)
        excludes = [a for a in fake.argv if a.startswith("--exclude=")]
        assert excludes and all("ash_output" in e for e in excludes)

    def test_no_exclude_when_the_output_directory_is_outside_the_tree(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDependencyCheck(tree)
        _run(scanner, fake, monkeypatch)
        assert not [a for a in fake.argv if a.startswith("--exclude=")]

    def test_the_timeout_reaches_the_subprocess(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDependencyCheck(tree)
        _run(scanner, fake, monkeypatch)
        timeout = fake.calls[0]["timeout"]
        assert (
            timeout is not None and 0 < timeout <= scanner.config.options.scan_timeout
        )


class TestNvdApiKey:
    def test_without_a_key_no_properties_file_is_passed(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDependencyCheck(tree)
        _run(scanner, fake, monkeypatch)
        assert not [a for a in fake.argv if a.startswith("--propertyfile=")]

    def test_the_key_goes_in_a_private_file_and_never_on_the_argv(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        monkeypatch.setenv(ds.NVD_API_KEY_ENV, FAKE_KEY)
        scanner = _scanner(tree, tmp_path)
        fake = FakeDependencyCheck(tree)
        _run(scanner, fake, monkeypatch)
        assert FAKE_KEY not in " ".join(fake.argv)
        assert fake.calls[0]["properties"] == f"nvd.api.key={FAKE_KEY}\n"
        if os.name == "posix":
            assert fake.calls[0]["properties_mode"] == 0o600

    def test_the_key_file_is_outside_the_scanned_tree(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        monkeypatch.setenv(ds.NVD_API_KEY_ENV, FAKE_KEY)
        scanner = _scanner(tree, tmp_path)
        fake = FakeDependencyCheck(tree)
        _run(scanner, fake, monkeypatch)
        path = Path(
            next(a for a in fake.argv if a.startswith("--propertyfile=")).split("=", 1)[
                1
            ]
        )
        assert not path.resolve().is_relative_to(tree.resolve())

    def test_a_newline_in_the_key_cannot_add_a_property(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        monkeypatch.setenv(ds.NVD_API_KEY_ENV, "abc\nanalyzer.retirejs.enabled=false")
        scanner = _scanner(tree, tmp_path)
        fake = FakeDependencyCheck(tree)
        _run(scanner, fake, monkeypatch)
        assert fake.calls[0]["properties"].count("\n") == 1


class TestReport:
    def test_the_report_is_rated_and_relocated(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeDependencyCheck(tree), monkeypatch)
        assert _findings(report) == EXPECTED

    def test_negative_control_a_report_with_no_vulnerabilities_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeDependencyCheck(tree, clean=True), monkeypatch)
        assert _findings(report) == []

    def test_level_and_severity_agree_on_every_result(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeDependencyCheck(tree), monkeypatch)
        agreed = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note",
        }
        for result in report.get_all_results():
            level = getattr(result.level, "value", result.level)
            assert agreed[result.properties.issue_severity] == level

    def test_results_are_marked_as_failures_and_tagged(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeDependencyCheck(tree), monkeypatch)
        for result in report.get_all_results():
            assert getattr(result.kind, "value", result.kind) == "fail"
            assert {"sca", "vulnerability", "security"} <= set(result.properties.tags)

    def test_a_uri_outside_the_source_directory_keeps_its_absolute_form(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        raw = sarif_for(tree)
        raw["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"] = "file:///opt/elsewhere/lib.jar"
        scanner = _scanner(tree, tmp_path)
        report = _run(
            scanner,
            FakeDependencyCheck(tree, sarif_text=json.dumps(raw)),
            monkeypatch,
        )
        assert _findings(report)[0][3] == "file:///opt/elsewhere/lib.jar"

    def test_a_result_whose_rule_is_missing_is_rated_medium(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        raw = sarif_for(tree)
        raw["runs"][0]["tool"]["driver"]["rules"] = []
        scanner = _scanner(tree, tmp_path)
        report = _run(
            scanner,
            FakeDependencyCheck(tree, sarif_text=json.dumps(raw)),
            monkeypatch,
        )
        assert {(f[1], f[2]) for f in _findings(report)} == {("warning", "MEDIUM")}

    def test_the_report_survives_a_round_trip_through_the_sarif_model(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeDependencyCheck(tree), monkeypatch)
        again = SarifReport.model_validate_json(
            report.model_dump_json(exclude_none=True, by_alias=True)
        )
        assert _findings(again) == EXPECTED


class TestSeverityRating:
    @pytest.mark.parametrize(
        "score, expected",
        [
            (10.0, ("CRITICAL", "error")),
            (9.0, ("CRITICAL", "error")),
            (8.9, ("HIGH", "error")),
            (7.0, ("HIGH", "error")),
            (6.9, ("MEDIUM", "warning")),
            (4.0, ("MEDIUM", "warning")),
            (3.9, ("LOW", "note")),
            (0.1, ("LOW", "note")),
            (0.0, ("INFO", "note")),
        ],
    )
    def test_cvss_score_bands(self, score, expected):
        assert severity_for_score(score) == expected

    @pytest.mark.parametrize(
        "properties, expected",
        [
            ({"security-severity": "9.8"}, ("CRITICAL", "error")),
            ({"security-severity": 5.0}, ("MEDIUM", "warning")),
            ({"cvssv2_severity": "HIGH"}, ("HIGH", "error")),
            ({"cvssv2_severity": " medium "}, ("MEDIUM", "warning")),
            ({"cvssv2_severity": "LOW"}, ("LOW", "note")),
            # The v3/v4 score wins over the v2 word.
            ({"security-severity": "2.0", "cvssv2_severity": "HIGH"}, ("LOW", "note")),
            ({"security-severity": "not a number"}, ("MEDIUM", "warning")),
            ({"cvssv2_severity": "SEVERE"}, ("MEDIUM", "warning")),
            ({}, ("MEDIUM", "warning")),
            (None, ("MEDIUM", "warning")),
            ("text", ("MEDIUM", "warning")),
        ],
    )
    def test_rule_properties(self, properties, expected):
        assert rate_rule(properties) == expected


class TestExitStatus:
    def test_zero_is_a_success(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeDependencyCheck(tree), monkeypatch)
        assert scanner._exit_code_accepted()

    def test_findings_do_not_change_the_exit_code(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """No --failOnCVSS, so a run with findings exits 0 and counts as finished."""
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeDependencyCheck(tree, exit_code=0), monkeypatch)
        assert len(_findings(report)) == len(RESULT_FILES)
        assert scanner.exit_code == 0

    @pytest.mark.parametrize("code", [1, 2, 4, 11, 12, 13, 14, 15, 126, 137])
    def test_any_other_exit_fails_the_scan_even_with_a_report_on_disk(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        """14 is a non-fatal analysis error: the report is partial."""
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeDependencyCheck(tree, exit_code=code), monkeypatch)

    def test_a_timeout_fails_the_scan_and_the_budget_reached_the_tool(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """A timed out run exits 124 and may have left a partial report."""
        scanner = _scanner(tree, tmp_path)
        fake = FakeDependencyCheck(tree, exit_code=124)
        with pytest.raises(ScannerError):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= scanner.config.options.scan_timeout

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeDependencyCheck(tree, write_report=False), monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        first = FakeDependencyCheck(tree)
        _run(scanner, first, monkeypatch)
        out = Path(
            next(a for a in first.argv if a.startswith("--out=")).split("=", 1)[1]
        )
        report = out / ds.REPORT_NAME
        assert report.exists(), "the first run left its report"
        with pytest.raises(ScannerError):
            _run(scanner, FakeDependencyCheck(tree, write_report=False), monkeypatch)
        assert not report.exists()

    def test_the_tools_stderr_is_not_copied_into_the_scans_errors(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner._process_command_response(
            {"returncode": 0, "stdout": "", "stderr": "analyzing PLANTED-FILE-NAME"}
        )
        assert not any("PLANTED-FILE-NAME" in line for line in scanner.errors)

    def test_the_failure_message_names_the_log_and_does_not_quote_it(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.exit_code = 14
        results = tmp_path / "out" / "source" / ds.REPORT_NAME
        message = scanner._describe_scan_failure(ScannerError("boom"), results)
        assert "stderr.log" in message
        assert "exit code 14" in message
        assert "not quoted" in message

    def test_a_failure_before_the_tool_started_has_no_exit_code(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        message = scanner._describe_scan_failure(
            ScannerError("boom"), None, tool_started=False
        )
        assert "was not started" in message
        assert "exit code" not in message


class TestMalformedOutput:
    @pytest.mark.parametrize(
        "text",
        [
            "this is not json",
            '{"runs": [',
            "[]",
            '"a string"',
            "{}",
            '{"runs": "nope"}',
            "",
            "   \n",
        ],
    )
    def test_output_that_is_not_a_sarif_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch, text
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(Exception) as caught:
            _run(scanner, FakeDependencyCheck(tree, sarif_text=text), monkeypatch)
        # Never a clean report: a tool that wrote garbage did not scan.
        assert not isinstance(caught.value, AssertionError)

    def test_a_result_that_is_not_an_object_does_not_crash_the_rating(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        raw = sarif_for(tree)
        raw["runs"][0]["results"].insert(0, "junk")
        scanner = _scanner(tree, tmp_path)
        try:
            _run(
                scanner,
                FakeDependencyCheck(tree, sarif_text=json.dumps(raw)),
                monkeypatch,
            )
        except ScannerError:
            return  # refused by the SARIF model, which is also right
        except Exception as exc:  # pragma: no cover - names the unexpected type
            pytest.fail(f"unexpected {type(exc).__name__}: {exc}")


class TestDependencyCheck:
    def test_a_missing_binary_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            ds,
            "find_executable",
            lambda cmd: "/fake/bin/java" if cmd == "java" else None,
        )
        scanner = _scanner(tree, tmp_path)
        monkeypatch.setattr(scanner, "_is_offline_mode", lambda: False)
        assert scanner.validate_plugin_dependencies() is False

    def test_a_missing_java_runtime_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            ds,
            "find_executable",
            lambda cmd: "/fake/bin/dependency-check" if cmd != "java" else None,
        )
        scanner = _scanner(tree, tmp_path)
        monkeypatch.setattr(scanner, "_is_offline_mode", lambda: False)
        assert scanner.validate_plugin_dependencies() is False

    def test_a_present_binary_and_java_satisfy_them(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        monkeypatch.setattr(scanner, "_is_offline_mode", lambda: False)
        assert scanner.validate_plugin_dependencies() is True

    def test_offline_the_scanner_is_skipped(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        monkeypatch.setattr(scanner, "_is_offline_mode", lambda: True)
        assert scanner.validate_plugin_dependencies() is False

    def test_a_missing_nvd_key_warns_and_does_not_block(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        monkeypatch.setattr(scanner, "_is_offline_mode", lambda: False)
        logged: List[str] = []
        monkeypatch.setattr(
            scanner, "_plugin_log", lambda message, **_: logged.append(str(message))
        )
        assert scanner.validate_plugin_dependencies() is True
        assert any("NVD_API_KEY" in m for m in logged)

    def test_an_unavailable_reason_blocks_it(self, tree, tmp_path, on_path):
        scanner = _scanner(tree, tmp_path)
        scanner.dependency_unavailable_reason = "refused"
        assert scanner.validate_plugin_dependencies() is False


class TestInstall:
    def test_install_commands_cover_every_platform_the_launcher_runs_on(self, tmp_path):
        scanner = _scanner(tmp_path, tmp_path)
        for platform, arch in [
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("darwin", "amd64"),
            ("darwin", "arm64"),
        ]:
            commands = scanner.get_installation_commands(platform, arch)
            assert commands, f"no install command for {platform}/{arch}"
            joined = " ".join(commands[0].args)
            assert DEPENDENCY_CHECK_URL in joined
            assert DEPENDENCY_CHECK_SHA256 in joined

    def test_windows_has_no_install_command_rather_than_an_empty_one(self, tmp_path):
        scanner = _scanner(tmp_path, tmp_path)
        assert "windows" not in scanner.custom_install_commands

    def test_the_pin_is_a_stable_release_with_a_full_digest(self):
        assert re.fullmatch(r"\d+\.\d+\.\d+", DEPENDENCY_CHECK_VERSION)
        assert re.fullmatch(r"[0-9a-f]{64}", DEPENDENCY_CHECK_SHA256)
        assert DEPENDENCY_CHECK_URL.startswith("https://github.com/")
        assert f"v{DEPENDENCY_CHECK_VERSION}/" in DEPENDENCY_CHECK_URL
        assert DEPENDENCY_CHECK_URL.endswith(f"{DEPENDENCY_CHECK_VERSION}-release.zip")

    def test_the_install_script_checks_the_digest_and_refuses_escaping_members(self):
        script = ds._INSTALL_SCRIPT
        assert "sha256 mismatch" in script
        assert "outside the install directory" in script
        compile(script, "<install script>", "exec")
