# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""MobsfscanScanner: the invocation, the exit status and the report.

The scan() tests replace the subprocess with a fake and the dependency check with a
stub, so they run on every platform without mobsfscan, uv or semgrep. Two kinds of
input drive them:

* ``tests/test_data/scanners/mobsfscan/captured/``: reports captured from a real
  mobsfscan 1.2.0 run (see its README), whose expected findings are written out by
  hand below, never derived from the code under test.
* ``POSITIVE`` below: a synthetic report built to the same shape, for the cases a
  capture cannot hold (a ``none`` level, a credential rule on an ``error``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_mobsfscan_plugins
from automated_security_helper.plugin_modules.ash_mobsfscan_plugins import (
    mobsfscan_scanner as ms,
)
from automated_security_helper.plugin_modules.ash_mobsfscan_plugins.mobsfscan_scanner import (
    MobsfscanScanner,
    MobsfscanScannerConfig,
    MobsfscanScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "mobsfscan"
    / "captured"
)


def _result(rule: str, level: str, uri: str, line: int, snippet: str) -> Dict[str, Any]:
    return {
        "ruleId": rule,
        "ruleIndex": 0,
        "level": level,
        "message": {"text": f"{rule} matched"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": line,
                        "endLine": line,
                        "startColumn": 1,
                        "endColumn": 20,
                        "snippet": {"text": snippet},
                    },
                }
            }
        ],
    }


def _sarif(results: List[Dict[str, Any]]) -> str:
    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "mobsfscan",
                            "informationUri": "https://github.com/MobSF/mobsfscan",
                            "semanticVersion": "1.2.0",
                            "version": "1.2.0",
                            "rules": [
                                {"id": r["ruleId"], "name": r["ruleId"]}
                                for r in results
                            ],
                        }
                    },
                    "results": results,
                }
            ],
        }
    )


#: One result per tool level, plus a ``none`` and a hard-coded-credential rule.
POSITIVE = _sarif(
    [
        _result("android_webview_debug", "error", "app/Main.java", 12, "setJavaScript"),
        _result("android_logging", "warning", "app/Log.java", 7, "Log.d(tag, msg)"),
        _result("android_prevent_screenshot", "note", "app/Act.java", 3, "onCreate"),
        _result("ios_unrated", "none", "ios/App.swift", 9, "let x = 1"),
        _result(
            "android_hardcoded_secret",
            "error",
            "app/Keys.java",
            5,
            "FAKE-NOT-A-REAL-VALUE",
        ),
    ]
)
NEGATIVE = _sarif([])

#: (ruleId, level ASH writes, ASH severity, uri, line), by hand from POSITIVE.
POSITIVE_EXPECTED = [
    ("android_webview_debug", "error", "HIGH", "app/Main.java", 12),
    ("android_logging", "warning", "MEDIUM", "app/Log.java", 7),
    ("android_prevent_screenshot", "note", "LOW", "app/Act.java", 3),
    ("ios_unrated", "warning", "MEDIUM", "ios/App.swift", 9),
    ("android_hardcoded_secret", "error", "HIGH", "app/Keys.java", 5),
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


class FakeMobsfscan:
    """Stands in for _run_subprocess: records the call, writes a report."""

    def __init__(
        self,
        sarif_text: Optional[str] = POSITIVE,
        exit_code: int = 0,
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
            output_arg = next(a for a in command if a.startswith("--output="))
            path = Path(output_arg.split("=", 1)[1])
            if self.sarif_text is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(self.sarif_text, encoding="utf-8")
            scanner.exit_code = self.exit_code
            response: Dict[str, Any] = {
                "returncode": self.exit_code,
                "stdout": "",
                "stderr": self.stderr,
            }
            if self.timed_out:
                response["timed_out"] = True
            return response

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(source: Path, tmp_path: Path, **options) -> MobsfscanScanner:
    output = tmp_path / "out"
    return MobsfscanScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=get_default_config(),
        ),
        config=MobsfscanScannerConfig(
            enabled=True, options=MobsfscanScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "app").mkdir(parents=True)
    (src / "app" / "Main.java").write_text("class Main {}\n")
    return src


def _run(scanner, fake, monkeypatch, target: Optional[Path] = None):
    # The dependency check would look for a real mobsfscan (the autouse unit tool
    # guard refuses to start one); the scan path under test starts at the fake.
    monkeypatch.setattr(
        MobsfscanScanner, "validate_plugin_dependencies", lambda self: True
    )
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type="source"
    )


class TestCommunityPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert MobsfscanScannerConfig().enabled is True
        assert MobsfscanScannerConfig().name == "mobsfscan"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "mobsfscan")

    def test_the_module_exports_the_scanner(self):
        assert ash_mobsfscan_plugins.ASH_SCANNERS == [MobsfscanScanner]
        assert ash_mobsfscan_plugins.ASH_REPORTERS == []

    def test_class_level_declarations(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        assert scanner.python_only is False
        assert scanner.success_exit_codes == {0}
        assert scanner.command == "mobsfscan"
        assert scanner.use_uv_tool is True


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(self, tree, tmp_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        fake = FakeMobsfscan()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[0] == "mobsfscan"
        assert "--sarif" in argv
        assert "--no-fail" in argv
        assert any(a.startswith("--output=") for a in argv)
        assert any(a.startswith("--config=") for a in argv)
        # The path follows "--", and for the source target it is ".".
        assert argv[-2:] == ["--", "."]

    def test_the_config_is_a_stub_outside_the_scanned_tree(
        self, tree, tmp_path, monkeypatch
    ):
        """A .mobsf in the tree can ignore rules and paths, so it is never read."""
        (tree / ".mobsf").write_text("ignore-rules:\n  - android_logging\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeMobsfscan()
        _run(scanner, fake, monkeypatch)
        config = Path(
            next(a for a in fake.argv if a.startswith("--config=")).split("=", 1)[1]
        )
        assert config != tree / ".mobsf"
        assert tree.resolve() not in config.resolve().parents

    def test_the_stub_config_ignores_nothing(self):
        assert ms.EMPTY_CONFIG_TEXT == "ignore-rules: []\n"

    @pytest.mark.parametrize(
        "forbidden",
        [
            "--exit-warning",
            "-w",
            "--html",
            "--json",
            "--sonarqube",
            "--gitlab-sast",
            "--type",
        ],
    )
    def test_flags_that_change_output_or_exit_status_are_never_passed(
        self, tree, tmp_path, monkeypatch, forbidden
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeMobsfscan()
        _run(scanner, fake, monkeypatch)
        assert forbidden not in fake.argv
        assert not any(a.startswith(forbidden + "=") for a in fake.argv)

    def test_a_converted_target_is_passed_as_an_absolute_path(
        self, tree, tmp_path, monkeypatch
    ):
        converted = tmp_path / "converted"
        converted.mkdir()
        (converted / "a.java").write_text("class A {}\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeMobsfscan()
        _run(scanner, fake, monkeypatch, target=converted)
        assert fake.argv[-2] == "--"
        assert fake.argv[-1] == converted.absolute().as_posix()

    def test_a_missing_target_never_reaches_the_tool(self, tree, tmp_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        fake = FakeMobsfscan()
        _run(scanner, fake, monkeypatch, target=tmp_path / "gone")
        assert fake.calls == []


class TestReport:
    def test_every_level_is_rated_and_located(self, tree, tmp_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeMobsfscan(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_the_clean_report_has_no_findings(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeMobsfscan(sarif_text=NEGATIVE), monkeypatch)
        assert _findings(report) == []

    def test_results_are_marked_as_failures(self, tree, tmp_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeMobsfscan(), monkeypatch)
        for result in report.get_all_results():
            assert getattr(result.kind, "value", result.kind) == "fail"

    def test_severity_and_level_agree_for_every_result(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeMobsfscan(), monkeypatch)
        by_severity = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
        for _rule, level, severity, _uri, _line in _findings(report):
            assert by_severity[severity] == level

    def test_a_result_without_a_level_is_medium(self, tree, tmp_path, monkeypatch):
        text = json.loads(_sarif([_result("ios_unrated", "none", "a.swift", 1, "x")]))
        del text["runs"][0]["results"][0]["level"]
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeMobsfscan(sarif_text=json.dumps(text)), monkeypatch)
        assert _findings(report) == [("ios_unrated", "warning", "MEDIUM", "a.swift", 1)]

    def test_a_hardcoded_credential_snippet_is_redacted(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeMobsfscan(), monkeypatch)
        snippets = {
            r.ruleId: r.locations[0].physicalLocation.root.region.snippet.text
            for r in report.get_all_results()
        }
        assert snippets["android_hardcoded_secret"] == "REDACTED"
        assert snippets["android_logging"] == "Log.d(tag, msg)"


class TestExitStatus:
    def test_zero_is_a_success(self, tree, tmp_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeMobsfscan(), monkeypatch)
        assert scanner._exit_code_accepted()

    @pytest.mark.parametrize("code", [1, 2, 126, 137])
    def test_nonzero_exit_fails_even_with_findings_on_disk(
        self, tree, tmp_path, monkeypatch, code
    ):
        """--no-fail makes 0 the only completed run; exit 1 is a crash."""
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeMobsfscan(exit_code=code), monkeypatch)

    def test_a_timeout_fails_the_scan_and_the_timeout_reaches_the_tool(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=5)
        fake = FakeMobsfscan(sarif_text=None, exit_code=124, timed_out=True)
        with pytest.raises(ScannerError):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 5

    @pytest.mark.parametrize(
        "text",
        ["{not json", "[]", '{"runs": []}', "   "],
        ids=["not-json", "not-an-object", "no-runs", "blank"],
    )
    def test_malformed_output_fails_the_scan(self, tree, tmp_path, monkeypatch, text):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeMobsfscan(sarif_text=text), monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeMobsfscan(sarif_text=None), monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_removed_before_the_next_one(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        first = FakeMobsfscan()
        _run(scanner, first, monkeypatch)
        report = Path(
            next(a for a in first.argv if a.startswith("--output=")).split("=", 1)[1]
        )
        assert report.exists()
        with pytest.raises(ScannerError):
            _run(scanner, FakeMobsfscan(sarif_text=None), monkeypatch)
        assert not report.exists()


class TestDependencyCheck:
    def test_an_unavailable_dependency_reason_fails_the_check(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        scanner.dependency_unavailable_reason = "not supported here"
        assert scanner.validate_plugin_dependencies() is False

    def test_tool_absent_everywhere_is_unsatisfied(self, tree, tmp_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        monkeypatch.setattr(scanner, "resolve_deferred_tool_version", lambda: None)
        monkeypatch.setattr(scanner, "_validate_uv_tool_availability", lambda: True)
        monkeypatch.setattr(
            scanner, "_get_tool_installation_info", lambda: {"available": False}
        )
        monkeypatch.setattr(scanner, "_install_uv_tool", lambda **_: False)
        monkeypatch.setattr(ms, "get_uv_tool_command", lambda *_a, **_k: None)
        monkeypatch.setattr(ms, "find_executable", lambda cmd: None)
        assert scanner.validate_plugin_dependencies() is False

    def test_a_pre_installed_tool_satisfies_the_check(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        monkeypatch.setattr(scanner, "resolve_deferred_tool_version", lambda: None)
        monkeypatch.setattr(scanner, "_validate_uv_tool_availability", lambda: False)
        monkeypatch.setattr(
            ms, "get_uv_tool_command", lambda *_a, **_k: ["/fake/bin/mobsfscan"]
        )
        assert scanner.validate_plugin_dependencies() is True


#: (ruleId, level ASH writes, ASH severity, uri, line) for captured/positive.sarif,
#: written by hand from the capture: aes_ecb_mode carries level "error", the two
#: warning rules carry no level at all (SARIF's default), the six Android
#: best-practice notes carry "note" and name no file ("."), and the credential rule
#: has its snippet redacted.
CAPTURED_POSITIVE_EXPECTED = [
    ("webview_set_allow_file_access", "warning", "MEDIUM", "Main.java", 8),
    ("hardcoded_password", "warning", "MEDIUM", "Main.java", 9),
    ("aes_ecb_mode", "error", "HIGH", "Main.java", 10),
    ("js_dynamic_code_execution", "warning", "MEDIUM", "app.js", 1),
    ("android_certificate_transparency", "note", "LOW", ".", 1),
    ("android_prevent_screenshot", "note", "LOW", ".", 1),
    ("android_detect_tapjacking", "note", "LOW", ".", 1),
    ("android_root_detection", "note", "LOW", ".", 1),
    ("android_certificate_pinning", "note", "LOW", ".", 1),
    ("android_safetynet_api", "note", "LOW", ".", 1),
]
BEST_PRACTICE_RULES = {
    "android_certificate_transparency",
    "android_prevent_screenshot",
    "android_detect_tapjacking",
    "android_root_detection",
    "android_certificate_pinning",
    "android_safetynet_api",
}


def _captured(name: str) -> str:
    return (CAPTURED / name).read_text(encoding="utf-8")


class TestCapturedReports:
    """The severity mapping and the report handling over real mobsfscan output."""

    def test_the_capture_carries_every_level_the_mapping_reads(self):
        """Guards the oracle: a capture with one level proves one mapping row."""
        results = json.loads(_captured("positive.sarif"))["runs"][0]["results"]
        assert {r.get("level") for r in results} == {"error", "note", None}

    def test_every_captured_result_is_rated_and_located(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeMobsfscan(sarif_text=_captured("positive.sarif"))
        report = _run(scanner, fake, monkeypatch)
        assert _findings(report) == CAPTURED_POSITIVE_EXPECTED

    def test_the_captured_credential_snippet_is_redacted(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeMobsfscan(sarif_text=_captured("positive.sarif"))
        report = _run(scanner, fake, monkeypatch)
        snippets = {
            r.ruleId: r.locations[0].physicalLocation.root.region.snippet.text
            for r in report.get_all_results()
        }
        assert snippets["hardcoded_password"] == "REDACTED"
        assert "not-a-real-password-fixture" not in report.model_dump_json()
        assert snippets["aes_ecb_mode"].strip().startswith("Cipher cipher")

    def test_negative_control_a_clean_tree_has_only_the_best_practice_notes(
        self, tree, tmp_path, monkeypatch
    ):
        """mobsfscan reports its Android best-practice rules on any tree."""
        scanner = _scanner(tree, tmp_path)
        fake = FakeMobsfscan(sarif_text=_captured("negative.sarif"))
        report = _run(scanner, fake, monkeypatch)
        found = _findings(report)
        assert {rule for rule, *_ in found} == BEST_PRACTICE_RULES
        assert {severity for _r, _l, severity, *_ in found} == {"LOW"}

    def test_a_scan_without_semgrep_reads_as_clean_in_sarif(
        self, tree, tmp_path, monkeypatch
    ):
        """Pins the failure the semgrep guard exists for: no JVM finding, no error.

        The capture is the same tree as positive.sarif run with semgrep off PATH.
        mobsfscan exited 0, its SARIF names no error, and the Java findings are
        absent: nothing in the report distinguishes it from a clean scan.
        """
        report = _run(
            _scanner(tree, tmp_path),
            FakeMobsfscan(sarif_text=_captured("semgrep_missing.sarif")),
            monkeypatch,
        )
        rules = {rule for rule, *_ in _findings(report)}
        assert {"hardcoded_password", "aes_ecb_mode"}.isdisjoint(rules)
        assert "semgrep" not in _captured("semgrep_missing.sarif").lower()
        # The JSON format of the same run does say it, which is why the guard
        # checks for semgrep before the run rather than reading the report.
        native = json.loads(_captured("semgrep_missing.json"))
        assert native["errors"] == [
            "semgrep not found. Install with: pip install semgrep"
        ]


class TestSemgrepOnPath:
    def test_through_uv_tool_run_nothing_is_added(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        assert scanner.use_uv_tool is True
        assert scanner._semgrep_env() is None

    def test_a_pre_installed_copy_gets_its_environments_bin_first_on_path(
        self, tree, tmp_path, monkeypatch
    ):
        env_bin = tmp_path / "toolenv" / "bin"
        env_bin.mkdir(parents=True)
        real = env_bin / "mobsfscan"
        real.write_text("#!/bin/sh\n")
        (env_bin / "semgrep").write_text("#!/bin/sh\n")
        (env_bin / "semgrep").chmod(0o755)
        shim_dir = tmp_path / "shims"
        shim_dir.mkdir()
        shim = shim_dir / "mobsfscan"
        shim.symlink_to(real)
        scanner = _scanner(tree, tmp_path)
        scanner.use_uv_tool = False
        monkeypatch.setattr(ms, "find_executable", lambda _cmd: shim.as_posix())
        monkeypatch.setattr(
            ms, "snapshot_environ", lambda: {"PATH": "/usr/bin", "HOME": "/h"}
        )
        env = scanner._semgrep_env()
        assert env is not None
        assert env["PATH"].split(":")[0] == env_bin.resolve().as_posix()
        assert env["HOME"] == "/h"

    def test_a_run_without_semgrep_is_refused_before_the_tool_starts(
        self, tree, tmp_path, monkeypatch
    ):
        bin_dir = tmp_path / "toolenv" / "bin"
        bin_dir.mkdir(parents=True)
        real = bin_dir / "mobsfscan"
        real.write_text("#!/bin/sh\n")
        scanner = _scanner(tree, tmp_path)
        scanner.use_uv_tool = False
        monkeypatch.setattr(ms, "find_executable", lambda _cmd: real.as_posix())
        monkeypatch.setattr(ms, "snapshot_environ", lambda: {"PATH": "/nonexistent"})
        fake = FakeMobsfscan()
        with pytest.raises(ScannerError, match="semgrep"):
            _run(scanner, fake, monkeypatch)
        assert fake.calls == []

    def test_the_path_copy_reaches_the_subprocess_with_the_adjusted_env(
        self, tree, tmp_path, monkeypatch
    ):
        bin_dir = tmp_path / "toolenv" / "bin"
        bin_dir.mkdir(parents=True)
        real = bin_dir / "mobsfscan"
        real.write_text("#!/bin/sh\n")
        (bin_dir / "semgrep").write_text("#!/bin/sh\n")
        (bin_dir / "semgrep").chmod(0o755)
        scanner = _scanner(tree, tmp_path)
        scanner.use_uv_tool = False
        monkeypatch.setattr(ms, "find_executable", lambda _cmd: real.as_posix())
        monkeypatch.setattr(ms, "snapshot_environ", lambda: {"PATH": "/usr/bin"})
        fake = FakeMobsfscan()
        _run(scanner, fake, monkeypatch)
        assert fake.calls[0]["env"]["PATH"].startswith(bin_dir.resolve().as_posix())


class TestInstall:
    def test_it_installs_as_a_uv_tool_with_the_pinned_version(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        assert scanner.uv_tool_install_commands
        assert scanner._get_tool_version_constraint() == "==1.2.0"

    def test_the_version_option_overrides_the_pin(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path, tool_version=">=1.2,<2")
        assert scanner._get_tool_version_constraint() == ">=1.2,<2"
